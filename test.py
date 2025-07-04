#!/usr/bin/env python3
"""
Gemini Code Review Bot - Test Script
This script demonstrates the code review bot with Gemini API
"""
import os
import tempfile
import json
from pathlib import Path
from langchain_google_genai import ChatGoogleGenerativeAI
def test_gemini_connection(api_key):
    """Test if Gemini API is working"""
    try:
        llm = ChatGoogleGenerativeAI( model="gemini-1.5-flash",google_api_key=api_key,temperature=0.1 )
        response = llm.invoke("Hello! Please respond with just 'API Working' if you can see this.")
        print(f"✅ Gemini API Connection: {response.content}")
        return True
    except Exception as e:
        print(f"❌ Gemini API Connection Failed: {e}")
        return False
def create_test_repository():
    """Create a test repository with various code issues"""
    repo_dir = tempfile.mkdtemp(prefix="gemini_code_review_")
    # Python file with multiple issues
    python_code = '''
import os
import sys
import json  # Unused import

def risky_function(user_input):
    """Function with security issues"""
   
    result = eval(user_input)
    return result

def divide_numbers(a, b):
   
    return a / b

def inefficient_search(items, target):
    """Inefficient search implementation"""
    found_items = []
    for i in range(len(items)):  # Can use enumerate
        for j in range(len(items)):  
            if items[i] == target:
                found_items.append(items[i])
    return found_items


def process_data(data):
    # TODO: Implement proper error handling
    processed = []
    for item in data:
        if item: 
            processed.append(item.upper())
    return processed

class DataProcessor:
    """Data processing class"""
    
    def __init__(self):
        self.data = []
    
    def add_item(self, item):
        self.data.append(item)
    
    def get_count(self):
        return len(self.data)
'''

    # JavaScript file with issues
    js_code = '''

function calculateSum(numbers) {
    var sum = 0;
    for (var i = 0; i < numbers.length; i++) {
        sum += numbers[i];
    }
    return sum;
}


function executeUserCode(code) {
    eval(code);
}


function updateMultipleElements() {
    for (var i = 0; i < 1000; i++) {
        document.getElementById('element' + i).innerHTML = 'Updated';
    }
}


function processUserInput(input) {return input.toUpperCase();}

var complexCalculation = function(a, b, c, d, e) { return a * b + c * d - e + Math.sqrt(a) + Math.pow(b, 2) + Math.sin(c) + Math.cos(d); };
'''

    # Create files
    with open(os.path.join(repo_dir, "main.py"), "w") as f:
        f.write(python_code)
    
    with open(os.path.join(repo_dir, "utils.js"), "w") as f:
        f.write(js_code)
    
    # Create a simple README (good practice)
    readme_content = """# Test Repository

This is a test repository for code review.

## Features
- Python utilities
- JavaScript helpers
"""
    
    with open(os.path.join(repo_dir, "README.md"), "w") as f:
        f.write(readme_content)
    
    return repo_dir

def run_simple_analysis(repo_path):
    """Run simple static analysis without AI"""
    print(f"🔍 Running simple analysis on: {repo_path}")
    issues = []
    files_analyzed = []
    for file_path in Path(repo_path).rglob("*"):
        if file_path.is_file() and file_path.suffix in ['.py', '.js', '.ts', '.java', '.cpp']:
            files_analyzed.append(str(file_path))
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            lines = content.split('\n')
            
            for i, line in enumerate(lines, 1):
                # Long lines
                if len(line.strip()) > 120:
                    issues.append({
                        'file': file_path.name,
                        'line': i,
                        'type': 'style',
                        'severity': 'minor',
                        'description': f'Line too long ({len(line)} characters)',
                        'code': line.strip()[:60] + '...'
                    })
                
                # TODO comments
                if 'TODO' in line or 'FIXME' in line:
                    issues.append({
                        'file': file_path.name,
                        'line': i,
                        'type': 'maintainability',
                        'severity': 'info',
                        'description': 'TODO/FIXME comment',
                        'code': line.strip()
                    })
                
                # Security issues
                if 'eval(' in line:
                    issues.append({
                        'file': file_path.name,
                        'line': i,
                        'type': 'security',
                        'severity': 'critical',
                        'description': 'Use of eval() - security risk',
                        'code': line.strip()
                    })
    
    return {
        'files_analyzed': len(files_analyzed),
        'issues': issues,
        'summary': {
            'total_issues': len(issues),
            'critical': len([i for i in issues if i['severity'] == 'critical']),
            'major': len([i for i in issues if i['severity'] == 'major']),
            'minor': len([i for i in issues if i['severity'] == 'minor']),
            'info': len([i for i in issues if i['severity'] == 'info'])
        }
    }

def run_ai_analysis(repo_path, api_key):
    """Run AI-powered analysis with Gemini"""
    print(f"🤖 Running AI analysis with Gemini...")
    
    try:
        llm = ChatGoogleGenerativeAI(
            model="gemini-1.5-flash",
            google_api_key=api_key,
            temperature=0.1
        )
        
        # Analyze the main Python file
        main_py_path = os.path.join(repo_path, "main.py")
        with open(main_py_path, 'r') as f:
            content = f.read()
        
        prompt = f"""
        Analyze this Python code and identify issues. Return ONLY a JSON array:
        
        ```python
        {content}
        ```
        
        Return format:
        [
          {{
            "line_number": 10,
            "issue_type": "security",
            "severity": "critical",
            "description": "Use of eval() creates security vulnerability",
            "suggested_fix": "Replace eval() with ast.literal_eval() or json.loads()"
          }}
        ]
        
        Focus on: bugs, security issues, performance problems, maintainability issues.
        Return only the JSON array.
        """
        
        response = llm.invoke(prompt)
        
        # Clean up response
        response_text = response.content.strip()
        if response_text.startswith("```json"):
            response_text = response_text[7:-3]
        elif response_text.startswith("```"):
            response_text = response_text[3:-3]
        
        ai_issues = json.loads(response_text)
        
        return ai_issues
        
    except Exception as e:
        print(f"⚠️ AI Analysis failed: {e}")
        return []

def print_detailed_report(static_results, ai_issues=None):
    """Print a detailed analysis report"""
    print("\n" + "="*70)
    print("🔍 GEMINI CODE REVIEW REPORT")
    print("="*70)
    
    # Summary
    print(f"\n📊 SUMMARY:")
    print(f"   Files analyzed: {static_results['files_analyzed']}")
    print(f"   Static issues found: {static_results['summary']['total_issues']}")
    if ai_issues:
        print(f"   AI issues found: {len(ai_issues)}")
    
    print(f"\n📈 ISSUE BREAKDOWN:")
    print(f"   🔴 Critical: {static_results['summary']['critical']}")
    print(f"   🟡 Major: {static_results['summary']['major']}")
    print(f"   🔵 Minor: {static_results['summary']['minor']}")
    print(f"   ℹ️  Info: {static_results['summary']['info']}")
    
    # Critical issues
    critical_issues = [i for i in static_results['issues'] if i['severity'] == 'critical']
    if critical_issues:
        print(f"\n🚨 CRITICAL ISSUES:")
        for issue in critical_issues:
            print(f"   📁 {issue['file']}:{issue['line']}")
            print(f"   🐛 {issue['description']}")
            print(f"   💻 {issue['code']}")
            print()
    
    # AI-detected issues
    if ai_issues:
        print(f"\n🤖 AI-DETECTED ISSUES:")
        for issue in ai_issues[:5]:  # Show top 5
            print(f"   📁 main.py:{issue.get('line_number', 'N/A')}")
            print(f"   🐛 {issue.get('description', 'N/A')}")
            if issue.get('suggested_fix'):
                print(f"   💡 Fix: {issue['suggested_fix']}")
            print()
    
    print("="*70)

def main():
    """Main test function"""
    print("🚀 Gemini Code Review Bot - Test Script")
    print("="*50)
    
    # Get API key
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("⚠️  GOOGLE_API_KEY environment variable not set")
        api_key = input("Enter your Gemini API key: ").strip()
    
    if not api_key:
        print("❌ No API key provided. Running static analysis only.")
        run_static_only
    else:
        # Test connection
        print("\n1. Testing Gemini API connection...")
        if test_gemini_connection(api_key):
            run_static_only = False
        else:
            print("❌ API connection failed. Running static analysis only.")
            run_static_only = True
    
    # Create test repository
    print("\n2. Creating test repository...")
    repo_path = create_test_repository()
    print(f"   Created test repo at: {repo_path}")
    
    # Run static analysis
    print("\n3. Running static analysis...")
    static_results = run_simple_analysis(repo_path)
    
    # Run AI analysis if possible
    ai_issues = None
    if not run_static_only:
        print("\n4. Running AI analysis with Gemini...")
        ai_issues = run_ai_analysis(repo_path, api_key)
        if ai_issues:
            print(f"   AI analysis found {len(ai_issues)} issues.")
        else:
            print("   No AI issues found or analysis failed.")
    else:
        print("   Skipping AI analysis due to API connection issues.")
    # Print detailed report
    print("\n5. Printing detailed report...")
    print_detailed_report(static_results, ai_issues)
    print("\n✅ Test completed successfully!")
    
if __name__ == "__main__":
    main()
# This script is designed to be run directly
# It will create a test repository, run static analysis, and optionally AI analysis
