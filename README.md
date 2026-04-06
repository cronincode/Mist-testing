These are tools to audit your Mist Org and configuration to help make sure it meets best practices

Requirements:

    pip install requests
 
Usage:

    export MIST_API_TOKEN="your_token_here"
    
    export MIST_ORG_ID="your_org_id_here"   # optional, auto-discovered if omitted
    
    python mist_org_audit.py               # terminal output only
    
    python mist_org_audit.py --csv         # + export findings.csv
    
    python mist_org_audit.py --html        # + export findings.html
    
    python mist_org_audit.py --csv --html  # both
    
run with --fix option to fix critical issues found 


use Streamlit for web front end. Run:


streamlit run mist_streamlit_audit_app.py
