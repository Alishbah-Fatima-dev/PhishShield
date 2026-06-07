import joblib
import re
import os

from threat_intel import (
    check_url_virustotal,
    format_vt_report,
    normalize_url
)

TRUSTED_DOMAINS = ["google.com","microsoft.com","github.com","openai.com","paypal.com","amazon.com","apple.com"]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, "phishing_model.pkl")
vectorizer_path = os.path.join(BASE_DIR, "vectorizer.pkl")
model = joblib.load(model_path)
vectorizer = joblib.load(vectorizer_path)

sus_words=["verify","account","password","otp","click","urgent","now","alert"]

sus_dic={ "gen":["verify","login","reward","prize","discount","lucky","now"],
         "pii":["name","address","account","visit","password","click","urgent","alert","warning"],
         "spi":["bank","credit","security","cnic","otp","password","address","process","transaction"]}

trusted_domains = [ "google", "microsoft","github", "paypal","amazon","facebook","apple"]

trusted_email_domains = ["gmail","outlook","yahoo","icloud","edu", "gov"]

phish_patterns=[{"bank", "login", "verify"},{"password", "click", "urgent"},
                {"account", "security", "alert"},{"otp", "bank", "transaction"}]

threat_categories = {
    "credential_harvesting": ["password", "login", "verify", "account", "otp"],
    "financial_scam": ["bank", "credit", "transaction", "payment"],
    "urgency_social_engineering": [ "urgent", "alert", "warning", "immediately", "now"],
    "suspicious_link": ["click", "secure", "update", "visit"]}

#--------------Cleaning extracted data----------------
def clean_items(list1):
    emp_list=[]
    for r in list1 :
        cln=r.strip()
        emp_list.append(cln)
    return emp_list
#---------------Parsing input------------------
def parser_input(text):
    text=text.lower()
    emails= re.findall(r'\S+@\S+',text)
    urls= re.findall(r'http://\S+|https://\S+|www\.\S+\.\S+',text)
    emails = clean_items(emails)
    urls = clean_items(urls)
    parsed_data= {
        "emails": emails,
        "urls": urls,
        "text": text}
    return parsed_data
#-------------tokenizer------------------
def tokenize_input(data):
    data = data.lower()
    tokens = re.split(r"[^\w]+", data)
    return tokens
#----------Handling input types--------------------
def detect_input_type(parsed_data):
    if parsed_data["emails"] and parsed_data["urls"]:
        return "mixed"
    elif parsed_data["emails"]:
        return "email"
    elif parsed_data["urls"]:
        return "url"
    return "text"
#------------Assigning Risk level--------
def risk_level(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    else:
        return "LOW"
#------------Email Analysis------------
def analyze_email(email):
    email_score = 0
    email_reasons = set()
    if "@" not in email:
        return 0, set()
    parts=email.split("@",1)
    if len(parts) != 2:
        return 0, set()
    username, domain = parts
    domain_tokens = tokenize_input(domain)
    user_tokens = tokenize_input(username)
    if any(char.isdigit() for char in username):
        email_score += 5
        email_reasons.add("Email username contains unusual numeric patterns")
    for token in user_tokens:
        if token in sus_dic.get("spi"):
            email_score += 10
            email_reasons.add("Sensitive/security-related wording detected in email username")
        elif token in sus_dic.get("pii"):
            email_score += 5
            email_reasons.add("Credential-targeting wording detected in email username")
    trusted = False
    for token in domain_tokens:
        if token in trusted_email_domains:
            trusted = True
            break
    if not trusted:
        email_score += 5
        email_reasons.add("Unknown or untrusted email domain detected")
    return email_score, email_reasons
#--------------main detection engine------------
feature_weights={ }
def cal_score(parsed_data):
    score=0
    vt_reasons = []
    rule_reasons = set()
    email_reasons = set()
    counted_tokens=set()
    all_tokens = set()
#-------------------text analysis-----------------
    text_tokens=parsed_data["text"].split()
    for token in text_tokens:
        token = token.strip("!.,?:;/").lower()
        if token in counted_tokens:
            continue
        if token in sus_dic.get("spi"):
            score+=15
            rule_reasons.add("Sensitive financial/security terms detected")
        elif token in sus_dic.get("pii"):
            score+=7
            rule_reasons.add("Credential targeting detected")
        elif token in sus_dic.get("gen"):
            score+=3
            rule_reasons.add("Urgency/manipulation detected")
        counted_tokens.add(token)
        all_tokens.add(token)
#----------------URL analysis---------------------
    for url in parsed_data.get("urls",[]):
        url_tokens = tokenize_input(url)
        for token in url_tokens:
            token=token.strip().lower()
            if token in counted_tokens:
                continue
            if token in sus_dic.get("spi"):
                score+=15
                rule_reasons.add("Sensitive financial/security terms detected")
            elif token in sus_dic.get("pii"):
                score+=7
                rule_reasons.add("Credential targeting detected")
            elif token in sus_dic.get("gen"):
                score+=3
                rule_reasons.add("Urgency/manipulation detected")
            counted_tokens.add(token)
            all_tokens.add(token)
        extra_score, extra_reasons = analyze_url(url)
        score += extra_score
        rule_reasons.update(extra_reasons)
#-------------------email analysis---------------------
    for email in parsed_data.get("emails", []):
        username, domain = email.split("@")
        if domain not in ["gmail.com", "yahoo.com", "outlook.com","microsoft.com"]:
            score += 15
            email_reasons.add("Untrusted Domain Detected")
        if any(char.isdigit() for char in username):
            score += 5
            email_reasons.add("Unusual numeric pattern in Email")
        email_tokens = tokenize_input(email)
        for token in email_tokens:
            token= token.strip().lower()
            if token in counted_tokens:
                continue
            if token in sus_dic.get("spi"):
                score += 15
                email_reasons.add("Sensitive financial/security terms detected")
            elif token in sus_dic.get("pii"):
                score += 7
                email_reasons.add("Credential targeting detected")
            elif token in sus_dic.get("gen"):
                score += 3
                email_reasons.add("Urgency/manipulation detected")
            counted_tokens.add(token)
            all_tokens.add(token)
        extra_score, extra_reasons = analyze_email(email)
        score += extra_score
        email_reasons.update(extra_reasons)
#---------------Pattern Correlation-------------
    extra_score, extra_reasons = analyze_patterns(all_tokens)
    score += extra_score
    rule_reasons.update(extra_reasons)
    vt_data = analyze_threat_intel(parsed_data.get("urls", []))
    vt_score = vt_data["score"]
    vt_reasons = vt_data["summary"]
    score += vt_score
#---------------Score Cap--------------
    if score>100:
        score=100
#---------------aggregating risk score--------
    ml_risk = ml_score(parsed_data["text"])
    score = (score * 0.6) + (ml_risk * 0.4)

    category = detect_threat_category(all_tokens)
# ---------- trusted domain override ----------
    if is_trusted_domain(parsed_data.get("urls", [])):
        score -= 25
        if score < 0:
            score = 0
    if score<=15:
        category = "trusted_service"
        rule_reasons.add( "Trusted domain reputation detected." )

    risk=risk_level(score)

    input_type = detect_input_type(parsed_data)
    all_reasons = rule_reasons.union(email_reasons).union(vt_reasons)
    ai_explanation = generate_ai_explanation(category,score,all_reasons,input_type)
    score = round(score, 2)

    return {
    "score": score,
    "risk": risk,
    "category": category,

    "threat_intelligence": {
        "summary": vt_reasons,
        "score": vt_score},

    "detection_indicators":list(rule_reasons),
    "email_indicators": list(email_reasons),

    "ai_explanation": ai_explanation}
#---------------URL analysis--------------
def analyze_url(url):
    url_score = 0
    url_reasons = set()
    tokens = tokenize_input(url)
    trusted = False
    for token in tokens:
        if token in trusted_domains:
            trusted = True
            break
    if not trusted:
        url_score += 5
        url_reasons.add("Unknown or untrusted domain detected")
    if url.count("-") >= 2:
        url_score += 3
        url_reasons.add("Hyphen-heavy domain structure detected")
    if len(url) > 40:
        url_score += 3
        url_reasons.add("Unusually long URL detected")
    return url_score, url_reasons
#-------------Pattern Correlation---------------
def analyze_patterns(all_tokens):
    pattern_score = 0
    pattern_reasons = set()
    for pattern in phish_patterns:
        if pattern.issubset(all_tokens):
            pattern_score += 20
            pattern_reasons.add("Multiple correlated phishing indicators detected")
    return pattern_score, pattern_reasons
#-------------checking trusted domains----------------
def is_trusted_domain(urls):
    for url in urls:
        for domain in TRUSTED_DOMAINS:
            if domain in url.lower():
                return True
    return False
#-----------------AI Categorization-------------
def detect_threat_category(all_tokens):
    category_scores = {}
    for category, keywords in threat_categories.items():
        score = 0
        for word in keywords:
            if word in all_tokens:
                score += 1
        category_scores[category] = score
    best_category = max(category_scores, key=category_scores.get)
    if category_scores[best_category] == 0:
        return "unknown"
    return best_category
#---------------AI generated explanation-------------
def generate_ai_explanation(category, score, reasons, input_type):
    if input_type == "url":
        base = "This URL was analyzed using domain reputation, threat intelligence sources, and heuristic signals."
    elif input_type == "email":
        base = "This email was analyzed for phishing indicators including sender reputation, content patterns, and social engineering tactics."
    elif input_type == "mixed":
        base = "This input contains both email and URL indicators analyzed for phishing behavior and external reputation signals."
    else:
        base = "This content was analyzed for general phishing and security risks."
    explanations = {
        "credential_harvesting":"This message appears to imitate a legitimate service and attempts to steal user credentials or authentication data.",
      
        "financial_scam":"The content contains financial and banking-related indicators commonly associated with phishing scams.",

        "urgency_social_engineering":"The message uses urgency and pressure tactics to manipulate the recipient into taking immediate action.",

        "suspicious_link":"The message contains suspicious links or redirection tactics often used in phishing campaigns.",

        "unknown":"Suspicious indicators were detected, but the threat pattern could not be confidently classified.",
         
        "brand_impersonation":"This message references a trusted service but contains suspicious indicators inconsistent with legitimate communication patterns.",
        
        "trusted_service":"Legitimate service indicators were detected. While some security-related language exists, the domain reputation appears trusted.",
    }
    explanation = explanations.get(category, "")

    if any("VirusTotal" in r for r in reasons):
        explanation += " External threat intelligence sources also reported malicious or suspicious activity related to the detected URLs."
    return base + " " + explanation
#-----------------Normalize URL--------------------
def normalize_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url 
#-----------------Threat intelligence Analysis---------------
def analyze_threat_intel(urls):
    vt_score = 0
    vt_reasons = []
    for url in urls:
        vt_result = check_url_virustotal(url)
        malicious = vt_result.get("malicious", 0)
        suspicious = vt_result.get("suspicious", 0)
        harmless = vt_result.get("harmless", 0)
        total_flags = malicious + suspicious
        if total_flags == 0:
            vt_score += 0
        elif malicious >= 5:
            vt_score += 30
        elif malicious >= 1:
            vt_score += 20
        elif suspicious >= 3:
            vt_score += 10
        report = format_vt_report(vt_result)
        if report:
           vt_reasons.append(report)
    return {
    "score": vt_score,
    "summary": vt_reasons}
#--------------Phishing Probability----------------
def ml_score(text):
    vec = vectorizer.transform([text])
    prob = model.predict_proba(vec)[0][1]  
    return prob * 100
#----------------testing----------------
# sample = """
# URGENT! Verify your bank account now.
# Click here:
# https://www.google.com at admin1@gmail.com
# """

# parsed = parser_input(sample)
# final_result = cal_score(parsed)
# print("\nRisk Score: ",final_result.get("score"))
# print("Risk Level: ",final_result["risk"])
# print("\nThreat Category: ",final_result["category"])
# print("\nThreat Intelligence Analysis:")
# vt = final_result["threat_intelligence"]
# for item in vt["summary"]:
#     print("-", item)
# print("\nAI Analysis:",final_result["ai_explanation"])