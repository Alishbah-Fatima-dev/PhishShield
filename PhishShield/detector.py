import re

sus_words=["verify","account","password","otp","click","urgent","now","alert"]
sus_dic={ "gen":["verify","login","reward","prize","discount","lucky","now"],
         "pii":["name","address","account","visit","password","click","urgent","alert","warning"],
         "spi":["bank","credit","security","cnic","otp","password","address","process","transaction"]}
trusted_domains = [ "google", "microsoft","github", "paypal","amazon","facebook","apple"]
trusted_email_domains = ["gmail","outlook","yahoo","icloud","edu", "gov"]

def clean_items(list1):
    emp_list=[]
    for r in list1 :
        cln=r.strip()
        emp_list.append(cln)
    return emp_list

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

def tokenize_input(data):
    data = data.lower()
    tokens = re.split(r"[^\w]+", data)
    return tokens

def risk_level(score):

    if score >= 70:
        return "CRITICAL"
    elif score >= 45:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    else:
        return "LOW"

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


feature_weights={ }
def cal_score(parsed_data):
    score=0
    reasons=set()
    counted_tokens=set()
#-------------------text analysis-----------------
    text_tokens=parsed_data["text"].split()
    for token in text_tokens:
        token = token.strip("!.,?:;/")
        if token in counted_tokens:
            continue
        if token in sus_dic.get("spi"):
            score+=15
            reasons.add("Sensitive financial/security terms detected")
        elif token in sus_dic.get("pii"):
            score+=7
            reasons.add("Credential targeting detected")
        elif token in sus_dic.get("gen"):
            score+=3
            reasons.add("Urgency/manipulation detected")
        counted_tokens.add(token)
#----------------URL analysis---------------------
    for url in parsed_data.get("urls",[]):
        tk_list = tokenize_input(url)
        for token in tk_list:
            if token in counted_tokens:
                continue
            if token in sus_dic.get("spi"):
                score+=15
                reasons.add("Sensitive financial/security terms detected")
            elif token in sus_dic.get("pii"):
                score+=7
                reasons.add("Credential targeting detected")
            elif token in sus_dic.get("gen"):
                score+=3
                reasons.add("Urgency/manipulation detected")
                counted_tokens.add(token)
        extra_score, extra_reasons = analyze_url(url)
        score += extra_score
        reasons.update(extra_reasons)
#-------------------email analysis---------------------
    for email in parsed_data.get("emails", []):
        username, domain = email.split("@")
        if domain not in ["gmail.com", "yahoo.com", "outlook.com","microsoft.com"]:
            score += 15
        if any(char.isdigit() for char in username):
            score += 5
        email_tokens = tokenize_input(email)
        for email in email_tokens:
            if token in counted_tokens:
                continue
            if token in sus_dic.get("spi"):
                score += 15
                reasons.add("Sensitive financial/security terms detected")
            elif token in sus_dic.get("pii"):
                score += 7
                reasons.add("Credential targeting detected")
            elif token in sus_dic.get("gen"):
                score += 3
                reasons.add("Urgency/manipulation detected")
            counted_tokens.add(token)
    extra_score, extra_reasons = analyze_email(email)
    score += extra_score
    reasons.update(extra_reasons)
#---------------limiting the total score
    if score>100:
        score=100
    risk=risk_level(score)
    return  {"score": score,
             "risk": risk,
             "reasons":list(reasons)}

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

#unit testing
sample = """
URGENT! Verify your bank account now.
Click here:
www.secure-bank-login.xyz at admin1@gmail.com
"""

parsed = parser_input(sample)
final_result = cal_score(parsed)
print("\nRisk Score: ",final_result.get("score"))
print("Risk Level: ",final_result["risk"])
print("\nReasons:")
for reason in final_result["reasons"]:
    print("-", reason)
