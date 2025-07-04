import ast
import re
import subprocess
import json
import tempfile
import os
from typing import Dict, List, Any, Optional, Tuple, Set, Union
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict
from dotenv import load_dotenv
import google.generativeai as genai
import time  # For rate limiting

load_dotenv()

@dataclass
class CodeIssue:
    """Represents a code issue found during review"""
    file_path: str
    line_number: int
    issue_type: str  # 'bug', 'style', 'performance', 'security', 'maintainability'
    severity: str    # 'critical', 'major', 'minor', 'info'
    description: str
    suggested_fix: Optional[str] = None
    code_snippet: Optional[str] = None
    source: str = "manual"  # 'manual', 'bandit', 'gemini', 'ast', 'taint'
    confidence: str = "medium"  # 'low', 'medium', 'high'
    cwe_id: Optional[str] = None
    bandit_test_id: Optional[str] = None
    context: Optional[str] = None  # Additional context about the issue
    taint_source: Optional[str] = None  # Source of tainted data


@dataclass
class TaintAnalysis:
    """Represents taint analysis results"""
    tainted_variables: Set[str] = field(default_factory=set)
    taint_sources: Dict[str, str] = field(default_factory=dict)  # variable -> source
    sanitized_variables: Set[str] = field(default_factory=set)
    dangerous_sinks: List[Tuple[str, int, str]] = field(default_factory=list)  # (func_name, line, context)


@dataclass
class ReviewState:
    """State object for the code review workflow"""
    repository_path: str = ""
    files_to_review: List[str] = field(default_factory=list)
    analyzed_files: List[str] = field(default_factory=list)
    issues: List[CodeIssue] = field(default_factory=list)
    bandit_issues: List[CodeIssue] = field(default_factory=list)
    gemini_issues: List[CodeIssue] = field(default_factory=list)
    ast_issues: List[CodeIssue] = field(default_factory=list)
    taint_issues: List[CodeIssue] = field(default_factory=list)
    cross_validated_issues: List[CodeIssue] = field(default_factory=list)
    documentation_issues: List[str] = field(default_factory=list)
    current_file: Optional[str] = None
    review_summary: Dict[str, Any] = field(default_factory=dict)
    validation_results: Dict[str, Any] = field(default_factory=dict)
    taint_analysis: Dict[str, TaintAnalysis] = field(default_factory=dict)


class ASTSecurityAnalyzer(ast.NodeVisitor):
    """AST-based security analyzer for Python code"""
    
    def __init__(self, file_path: str, source_lines: List[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.issues = []
        self.current_function = None
        self.imports = {}  # module -> alias mapping
        self.taint_analysis = TaintAnalysis()
        
        # Define dangerous functions and their contexts
        self.dangerous_functions = {
            'eval': {'severity': 'critical', 'cwe': 'CWE-95'},
            'exec': {'severity': 'critical', 'cwe': 'CWE-95'},
            'compile': {'severity': 'major', 'cwe': 'CWE-95'},
            'open': {'severity': 'minor', 'cwe': 'CWE-73'},  # Only dangerous with user input
            'pickle.loads': {'severity': 'critical', 'cwe': 'CWE-502'},
            'pickle.load': {'severity': 'critical', 'cwe': 'CWE-502'},
            'os.system': {'severity': 'critical', 'cwe': 'CWE-78'},
            'subprocess.call': {'severity': 'major', 'cwe': 'CWE-78'},
            'subprocess.run': {'severity': 'major', 'cwe': 'CWE-78'},
            'subprocess.Popen': {'severity': 'major', 'cwe': 'CWE-78'},
        }
        
        # Define taint sources (user input sources)
        self.taint_sources = {
            'input': 'user_input',
            'sys.argv': 'command_line',
            'os.environ': 'environment',
            'request.args': 'web_request',
            'request.form': 'web_request',
            'request.json': 'web_request',
            'request.data': 'web_request',
            'flask.request': 'web_request',
            'django.request': 'web_request',
        }
        
        # Define sanitization functions
        self.sanitizers = {
            'escape', 'quote', 'quote_plus', 'html.escape', 'bleach.clean',
            'validate', 'sanitize', 'clean', 'filter', 'whitelist'
        }
    
    def visit_Import(self, node: ast.Import):
        """Track imports for better context analysis"""
        for alias in node.names:
            self.imports[alias.name] = alias.asname if alias.asname else alias.name
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track from imports"""
        if node.module:
            for alias in node.names:
                import_name = f"{node.module}.{alias.name}"
                self.imports[import_name] = alias.asname if alias.asname else alias.name
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Track current function context"""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_Call(self, node: ast.Call):
        """Analyze function calls for security issues"""
        func_name = self._get_function_name(node.func)
        line_number = node.lineno
        
        # Check if this is a dangerous function
        if func_name in self.dangerous_functions:
            self._analyze_dangerous_call(node, func_name, line_number)
        
        # Check for SQL injection patterns
        if self._is_sql_method(func_name):
            self._analyze_sql_call(node, func_name, line_number)
        
        # Check for subprocess with shell=True
        if 'subprocess' in func_name and self._has_shell_true(node):
            self._analyze_subprocess_shell(node, func_name, line_number)
        
        # Track taint propagation
        self._track_taint_propagation(node, func_name, line_number)
        
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign):
        """Track variable assignments for taint analysis"""
        # Check if assignment involves tainted data or sanitization
        if isinstance(node.value, ast.Call):
            func_name = self._get_function_name(node.value.func)
            # Taint source
            if func_name in self.taint_sources:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.taint_analysis.tainted_variables.add(target.id)
                        self.taint_analysis.taint_sources[target.id] = self.taint_sources[func_name]
            # Sanitization
            elif any(sanitizer in func_name.lower() for sanitizer in self.sanitizers):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.taint_analysis.sanitized_variables.add(target.id)
                        self.taint_analysis.tainted_variables.discard(target.id)
            # Propagate taint from variables
            else:
                tainted = False
                if hasattr(node.value, 'args'):
                    for arg in node.value.args:
                        if isinstance(arg, ast.Name) and arg.id in self.taint_analysis.tainted_variables:
                            tainted = True
                if tainted:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.taint_analysis.tainted_variables.add(target.id)
        # Propagate taint through direct assignment
        elif isinstance(node.value, ast.Name):
            if node.value.id in self.taint_analysis.tainted_variables:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.taint_analysis.tainted_variables.add(target.id)
        self.generic_visit(node)
    
    def _get_function_name(self, func_node: ast.AST) -> str:
        """Extract function name from AST node"""
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            # Recursively get full attribute chain
            value = self._get_function_name(func_node.value)
            return f"{value}.{func_node.attr}" if value else func_node.attr
        elif isinstance(func_node, ast.Call):
            return self._get_function_name(func_node.func)
        elif isinstance(func_node, ast.Subscript):
            return self._get_function_name(func_node.value)
        elif isinstance(func_node, ast.Lambda):
            return "<lambda>"
        else:
            return getattr(func_node, 'id', str(func_node))
    
    def _analyze_dangerous_call(self, node: ast.Call, func_name: str, line_number: int):
        """Analyze dangerous function calls with context"""
        danger_info = self.dangerous_functions[func_name]
        
        # Check if arguments are tainted
        tainted_args = []
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in self.taint_analysis.tainted_variables:
                tainted_args.append(arg.id)
        
        # Determine severity based on taint analysis
        if tainted_args:
            severity = danger_info['severity']
            description = f"Dangerous function '{func_name}' called with tainted input: {', '.join(tainted_args)}"
            confidence = 'high'
        else:
            # Check if arguments are literals or constants
            if all(isinstance(arg, (ast.Constant, ast.Str, ast.Num)) for arg in node.args):
                severity = 'minor'
                description = f"Dangerous function '{func_name}' called with literal arguments (lower risk)"
                confidence = 'medium'
            else:
                severity = 'major'
                description = f"Dangerous function '{func_name}' called with dynamic arguments"
                confidence = 'medium'
        
        # Get code snippet
        code_snippet = self._get_code_snippet(line_number)
        
        # Check for sanitization context
        context = self._analyze_sanitization_context(node, line_number)
        
        issue = CodeIssue(
            file_path=self.file_path,
            line_number=line_number,
            issue_type='security',
            severity=severity,
            description=description,
            code_snippet=code_snippet,
            source='ast',
            confidence=confidence,
            cwe_id=danger_info['cwe'],
            context=context,
            taint_source=self.taint_analysis.taint_sources.get(tainted_args[0]) if tainted_args else None
        )
        
        self.issues.append(issue)
    
    def _analyze_sql_call(self, node: ast.Call, func_name: str, line_number: int):
        """Analyze SQL calls for injection vulnerabilities"""
        if not node.args:
            return
        
        # Check first argument (usually the SQL query)
        sql_arg = node.args[0]
        
        # Look for string formatting or concatenation
        if isinstance(sql_arg, ast.BinOp) and isinstance(sql_arg.op, ast.Mod):
            # String formatting with %
            issue = CodeIssue(
                file_path=self.file_path,
                line_number=line_number,
                issue_type='security',
                severity='critical',
                description=f"SQL injection vulnerability: {func_name} uses string formatting",
                code_snippet=self._get_code_snippet(line_number),
                source='ast',
                confidence='high',
                cwe_id='CWE-89'
            )
            self.issues.append(issue)
        
        elif isinstance(sql_arg, ast.BinOp) and isinstance(sql_arg.op, ast.Add):
            # String concatenation
            issue = CodeIssue(
                file_path=self.file_path,
                line_number=line_number,
                issue_type='security',
                severity='critical',
                description=f"SQL injection vulnerability: {func_name} uses string concatenation",
                code_snippet=self._get_code_snippet(line_number),
                source='ast',
                confidence='high',
                cwe_id='CWE-89'
            )
            self.issues.append(issue)
    
    def _is_sql_method(self, func_name: str) -> bool:
        """Check if function is a SQL execution method"""
        sql_methods = {'execute', 'executemany', 'cursor.execute', 'cursor.executemany'}
        return func_name in sql_methods or func_name.endswith('.execute')
    
    def _has_shell_true(self, node: ast.Call) -> bool:
        """Check if call has shell=True parameter"""
        for keyword in node.keywords:
            if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                return keyword.value.value is True
        return False
    
    def _analyze_subprocess_shell(self, node: ast.Call, func_name: str, line_number: int):
        """Analyze subprocess calls with shell=True"""
        # Check if command argument is tainted
        if node.args:
            cmd_arg = node.args[0]
            if isinstance(cmd_arg, ast.Name) and cmd_arg.id in self.taint_analysis.tainted_variables:
                severity = 'critical'
                description = f"Command injection: {func_name} with shell=True and tainted input"
                confidence = 'high'
            else:
                severity = 'major'
                description = f"Potential command injection: {func_name} with shell=True"
                confidence = 'medium'
            
            issue = CodeIssue(
                file_path=self.file_path,
                line_number=line_number,
                issue_type='security',
                severity=severity,
                description=description,
                code_snippet=self._get_code_snippet(line_number),
                source='ast',
                confidence=confidence,
                cwe_id='CWE-78'
            )
            self.issues.append(issue)
    
    def _track_taint_propagation(self, node: ast.Call, func_name: str, line_number: int):
        """Track how taint propagates through function calls"""
        # Mark as taint source
        if func_name in self.taint_sources:
            self.taint_analysis.dangerous_sinks.append((func_name, line_number, 'taint_source'))
        # Propagate taint through function arguments
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in self.taint_analysis.tainted_variables:
                # Mark return value as tainted if assigned
                parent = getattr(node, 'parent', None)
                if isinstance(parent, ast.Assign):
                    for target in parent.targets:
                        if isinstance(target, ast.Name):
                            self.taint_analysis.tainted_variables.add(target.id)

    def _analyze_sanitization_context(self, node: ast.Call, line_number: int) -> Optional[str]:
        """Analyze if there's sanitization context around the call"""
        # Simple heuristic: check surrounding lines for sanitization keywords
        start_line = max(0, line_number - 3)
        end_line = min(len(self.source_lines), line_number + 2)
        
        context_lines = self.source_lines[start_line:end_line]
        context_text = '\n'.join(context_lines)
        
        for sanitizer in self.sanitizers:
            if sanitizer in context_text.lower():
                return f"Potential sanitization detected: {sanitizer}"
        
        return None
    
    def _get_code_snippet(self, line_number: int) -> str:
        """Get code snippet for the given line"""
        if 0 <= line_number - 1 < len(self.source_lines):
            return self.source_lines[line_number - 1].strip()
        return ""


class EnhancedCodeReviewBot:
    """Enhanced code review bot with AST-based analysis and taint tracking"""
    
    def __init__(self, gemini_api_key: str = None):
        """Initialize the Enhanced Code Review Bot"""
        if not gemini_api_key:
            raise ValueError("Gemini API key is required")
        
        genai.configure(api_key=gemini_api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')
        self.bandit_available = self._check_bandit_availability()
        self.supported_extensions = {'.py', '.js', '.ts', '.java', '.cpp', '.c', '.cs', '.go', '.rs', '.php', '.rb', '.swift', '.kt'}
        
        # Deprecated regex patterns for comparison
        self.legacy_patterns = {
            'eval_usage': r'eval\s*\(',
            'exec_usage': r'exec\s*\(',
            'pickle_loads': r'pickle\.loads?\s*\(',
            'os_system': r'os\.system\s*\(',
            'subprocess_shell': r'subprocess\.[a-zA-Z_]*\([^)]*shell\s*=\s*True',
        }
    
    def _check_bandit_availability(self) -> bool:
        """Check if Bandit is installed and available"""
        try:
            result = subprocess.run(['bandit', '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✅ Bandit is available")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        print("⚠️ Bandit not found. Install with: pip install bandit")
        return False
    
    def _parse_files(self, state: ReviewState) -> ReviewState:
        """Parse repository and identify files to review"""
        print(f"🔍 Parsing files in: {state.repository_path}")
        
        repo_path = Path(state.repository_path)
        
        if repo_path.is_file():
            if repo_path.suffix in self.supported_extensions:
                state.files_to_review = [str(repo_path)]
                print(f"📁 Single file to review: {repo_path.name}")
            else:
                print(f"❌ Unsupported file type: {repo_path.suffix}")
            return state
        
        if not repo_path.exists():
            print(f"❌ Path does not exist: {state.repository_path}")
            return state
        
        files_to_review = []
        for file_path in repo_path.rglob("*"):
            if file_path.is_file() and file_path.suffix in self.supported_extensions:
                if any(ignore in str(file_path) for ignore in ['.git', '__pycache__', 'node_modules', '.env']):
                    continue
                files_to_review.append(str(file_path))
        
        state.files_to_review = files_to_review
        print(f"📁 Found {len(files_to_review)} files to review")
        
        return state
    
    def _run_ast_analysis(self, state: ReviewState) -> ReviewState:
        """Run AST-based security analysis"""
        print("🌳 Running AST-based security analysis...")

        python_files = [f for f in state.files_to_review if f.endswith('.py')]

        if not python_files:
            print("ℹ️ No Python files found for AST analysis")
            return state

        for file_path in python_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    # Read only first 10000 lines for memory efficiency
                    source_lines = []
                    for i, line in enumerate(f):
                        if i > 10000:
                            source_lines.append("# ... (truncated)")
                            break
                        source_lines.append(line.rstrip('\n'))
                    source_code = '\n'.join(source_lines)

                tree = ast.parse(source_code)
                # Set parent attribute for taint propagation
                for node in ast.walk(tree):
                    for child in ast.iter_child_nodes(node):
                        child.parent = node

                analyzer = ASTSecurityAnalyzer(file_path, source_lines)
                analyzer.visit(tree)

                state.ast_issues.extend(analyzer.issues)
                state.issues.extend(analyzer.issues)
                state.taint_analysis[file_path] = analyzer.taint_analysis

            except SyntaxError as e:
                issue = CodeIssue(
                    file_path=file_path,
                    line_number=e.lineno or 0,
                    issue_type='bug',
                    severity='critical',
                    description=f"Syntax error: {e.msg}",
                    source='ast',
                    confidence='high'
                )
                state.issues.append(issue)
            except Exception as e:
                print(f"⚠️ Error analyzing {file_path}: {e}")

        print(f"🌳 AST analysis found {len(state.ast_issues)} issues")
        return state
    
    def _run_bandit_analysis(self, state: ReviewState) -> ReviewState:
        """Run Bandit security analysis"""
        print("🛡️ Running Bandit security analysis...")

        if not self.bandit_available:
            print("⚠️ Skipping Bandit analysis - not available")
            return state

        python_files = [f for f in state.files_to_review if f.endswith('.py')]

        if not python_files:
            print("ℹ️ No Python files found for Bandit analysis")
            return state

        try:
            # Bandit expects file paths directly, not --files
            cmd = ['bandit', '-f', 'json', '-ll'] + python_files
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.stdout:
                bandit_data = json.loads(result.stdout)
                self._parse_bandit_results(bandit_data, state)

        except subprocess.TimeoutExpired:
            print("⚠️ Bandit analysis timed out")
        except json.JSONDecodeError:
            print("⚠️ Error parsing Bandit JSON output")
        except Exception as e:
            print(f"⚠️ Error running Bandit: {e}")

        return state
    
    def _parse_bandit_results(self, bandit_data: Dict, state: ReviewState):
        """Parse Bandit results and convert to CodeIssue objects"""
        for result in bandit_data.get('results', []):
            severity_map = {'HIGH': 'critical', 'MEDIUM': 'major', 'LOW': 'minor'}
            confidence_map = {'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low'}
            
            issue = CodeIssue(
                file_path=result['filename'],
                line_number=result['line_number'],
                issue_type='security',
                severity=severity_map.get(result['issue_severity'], 'minor'),
                description=f"[Bandit] {result['issue_text']}",
                code_snippet=result.get('code', '').strip(),
                source='bandit',
                confidence=confidence_map.get(result['issue_confidence'], 'medium'),
                cwe_id=result.get('cwe', {}).get('id'),
                bandit_test_id=result['test_id']
            )
            
            state.bandit_issues.append(issue)
            state.issues.append(issue)
        
        print(f"🛡️ Bandit found {len(state.bandit_issues)} security issues")
    
    def _cross_validate_issues(self, state: ReviewState) -> ReviewState:
        """Cross-validate issues between AST and Bandit analysis"""
        print("🔍 Cross-validating issues between AST and Bandit analysis...")
        
        # Group issues by file and fuzzy line number (±2 lines)
        def fuzzy_key(issue):
            return (issue.file_path, issue.line_number // 5)  # group by 5-line buckets

        issue_groups = defaultdict(list)
        for issue in state.issues:
            issue_groups[fuzzy_key(issue)].append(issue)

        agreements = []
        ast_unique = []
        bandit_unique = []

        for key, issues in issue_groups.items():
            ast_issues = [i for i in issues if i.source == 'ast']
            bandit_issues = [i for i in issues if i.source == 'bandit']

            if ast_issues and bandit_issues:
                agreements.extend(ast_issues + bandit_issues)
                for issue in ast_issues + bandit_issues:
                    if issue.confidence == 'medium':
                        issue.confidence = 'high'
            elif ast_issues:
                ast_unique.extend(ast_issues)
            elif bandit_issues:
                bandit_unique.extend(bandit_issues)

        state.validation_results = {
            'total_issues': len(state.issues),
            'ast_issues': len(state.ast_issues),
            'bandit_issues': len(state.bandit_issues),
            'agreements': len(agreements),
            'ast_unique': len(ast_unique),
            'bandit_unique': len(bandit_unique),
            'agreement_rate': len(agreements) / len(state.issues) if state.issues else 0
        }
        
        print(f"📊 Validation: {len(agreements)} agreements, {len(ast_unique)} AST-only, {len(bandit_unique)} Bandit-only")
        
        return state
    
    def _run_taint_analysis(self, state: ReviewState) -> ReviewState:
        """Run enhanced taint analysis"""
        print("🔬 Running enhanced taint analysis...")
        
        taint_issues = []
        
        for file_path, taint_data in state.taint_analysis.items():
            # Check for tainted data reaching dangerous sinks
            for sink_name, line_num, context in taint_data.dangerous_sinks:
                if taint_data.tainted_variables:
                    issue = CodeIssue(
                        file_path=file_path,
                        line_number=line_num,
                        issue_type='security',
                        severity='major',
                        description=f"Tainted data flow detected: {sink_name} may receive untrusted input",
                        source='taint',
                        confidence='high',
                        context=context
                    )
                    taint_issues.append(issue)
        
        state.taint_issues = taint_issues
        state.issues.extend(taint_issues)
        
        print(f"🔬 Taint analysis found {len(taint_issues)} data flow issues")
        
        return state
    
    def _gemini_semantic_analysis(self, state: ReviewState) -> ReviewState:
        """Enhanced Gemini analysis with context from AST/Bandit"""
        print("🧠 Running Gemini semantic analysis with context...")
        
        # Focus on files with existing issues for deeper analysis
        files_with_issues = set(issue.file_path for issue in state.issues)
        priority_files = list(files_with_issues)[:3]  # Limit for performance
        
        for file_path in priority_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = ""
                    for i, line in enumerate(f):
                        if i > 4000:
                            content += "\n# ... (truncated)"
                            break
                        content += line

                existing_issues = [i for i in state.issues if i.file_path == file_path]

                gemini_issues = self._analyze_with_enhanced_gemini(file_path, content, existing_issues)
                state.gemini_issues.extend(gemini_issues)
                state.issues.extend(gemini_issues)

                # Rate limiting to avoid API quota exhaustion
                time.sleep(2)

            except Exception as e:
                print(f"⚠️ Error in Gemini analysis for {file_path}: {e}")
        
        print(f"🧠 Gemini found {len(state.gemini_issues)} additional semantic issues")
        
        return state
    
    def _analyze_with_enhanced_gemini(self, file_path: str, content: str, existing_issues: List[CodeIssue]) -> List[CodeIssue]:
        """Enhanced Gemini analysis with context from other tools"""
        
        # Build context from existing issues
        context_info = ""
        if existing_issues:
            context_info = "\nExisting issues found by AST/Bandit analysis:\n"
            for issue in existing_issues[:5]:
                context_info += f"- Line {issue.line_number}: {issue.description} (Source: {issue.source})\n"
        
        prompt = f"""
        You are a senior security engineer reviewing code that has already been analyzed by AST-based tools and Bandit.
        
        File: {file_path}
        {context_info}
        
        Code:
        ```python
        {content}
        ```
        
        Focus on HIGH-LEVEL semantic issues that AST analysis might miss:
        1. Business logic flaws that could bypass security controls
        2. Race conditions and timing attacks
        3. Authentication/authorization bypass patterns
        4. Complex data validation bypasses
        5. Cryptographic implementation flaws
        6. Session management vulnerabilities
        7. Information disclosure through error handling
        
        CRITICAL: Only report issues NOT already found by the tools above.
        Focus on CONTEXT-AWARE analysis that requires understanding program flow.
        
        Return ONLY a JSON array:
        [
          {{
            "line_number": 25,
            "issue_type": "security",
            "severity": "critical",
            "description": "Business logic flaw allows privilege escalation",
            "suggested_fix": "Add role-based access control checks",
            "confidence": "high"
          }}
        ]
        
        Return only the JSON array, no other text.
        """
        
        try:
            response = self.model.generate_content(prompt)
            response_text = response.text.strip()
            
            # Clean JSON response
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.startswith("```"):
                response_text = response_text[3:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            
            try:
                issues_data = json.loads(response_text.strip())
            except json.JSONDecodeError:
                # Try to recover from malformed JSON
                response_text = re.sub(r'^[^\[]*', '', response_text)  # Remove leading non-[ chars
                response_text = re.sub(r'[^\]]*$', '', response_text)  # Remove trailing non-] chars
                try:
                    issues_data = json.loads(response_text.strip())
                except Exception:
                    print(f"⚠️ Gemini response parsing error for {file_path}: {response_text}")
                    return []

            issues = []
            for issue_data in issues_data:
                if not all(key in issue_data for key in ['line_number', 'issue_type', 'severity', 'description']):
                    continue
                
                issue = CodeIssue(
                    file_path=file_path,
                    line_number=int(issue_data['line_number']),
                    issue_type=issue_data['issue_type'],
                    severity=issue_data['severity'],
                    description=f"[Gemini] {issue_data['description']}",
                    suggested_fix=issue_data.get('suggested_fix'),
                    source='gemini',
                    confidence=issue_data.get('confidence', 'medium'),
                    context=issue_data.get('context'),
                    taint_source=issue_data.get('taint_source')
                )
                issues.append(issue)
            return issues
        except Exception as e:
            print(f"⚠️ Gemini API/network error for {file_path}: {e}")
            return []

    def run_review(self, state: ReviewState) -> ReviewState:
        """Run the complete code review workflow"""
        print("🚀 Starting code review workflow...")
        
        # Step 1: Parse files
        state = self._parse_files(state)
        
        # Step 2: Run AST analysis
        state = self._run_ast_analysis(state)
        
        # Step 3: Run Bandit analysis
        state = self._run_bandit_analysis(state)
        
        # Step 4: Cross-validate issues
        state = self._cross_validate_issues(state)
        
        # Step 5: Run enhanced taint analysis
        state = self._run_taint_analysis(state)
        
        # Step 6: Run Gemini semantic analysis
        state = self._gemini_semantic_analysis(state)
        
        print("🚀 Code review workflow completed")
        return state

def run_code_review(repository_path: str, gemini_api_key: str) -> ReviewState:
    """Run the complete code review process for a given repository"""
    bot = EnhancedCodeReviewBot(gemini_api_key)
    state = ReviewState(repository_path=repository_path)

    # Run the review workflow
    state = bot.run_review(state)

    # Print summary
    print(f"🔍 Code review completed for {repository_path}")
    print(f"Total issues found: {len(state.issues)}")
    print(f"AST issues: {len(state.ast_issues)}")
    print(f"Bandit issues: {len(state.bandit_issues)}")
    print(f"Gemini issues: {len(state.gemini_issues)}")
    print(f"Taint issues: {len(state.taint_issues)}")

    return state

if __name__ == "__main__":
    import argparse
    from dotenv import load_dotenv

    load_dotenv()

    parser = argparse.ArgumentParser(description="Enhanced Code Review Bot")
    parser.add_argument("repository_path", type=str, help="Path to the repository to review")


    args = parser.parse_args()

    # Run the code review
    run_code_review(args.repository_path, os.getenv("GEMINI_API_KEY"))