import re

sus_words=["verify","account","password","otp","click","urgent","now","alert"]
sus_dic={ "gen":["verify","login","reward","prize","discount","lucky","now"],
         "pii":["name","address","account","visit","password","click","urgent","alert","warning"],
         "spi":["bank","credit","security","cnic","otp","password","address","process","transaction"]}

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

feature_weights={ }
def cal_score(parsed_data):
    score=0
    text_tokens=parsed_data["text"].split()
    for text in text_tokens:
        if text in sus_dic.get("spi"):
            score+=15
        elif text in sus_dic.get("pii"):
            score+=10
        elif text in sus_dic.get("gen"):
            score+=5

    for url in parsed_data.get("urls",[]):
        tk_list = tokenize_input(url)
        for token in tk_list:
            if token in sus_dic.get("spi"):
                score+=15
            elif token in sus_dic.get("pii"):
                score+=10
            elif token in sus_dic.get("gen"):
                score+=5

    for email in parsed_data.get("emails", []):
        username, domain = email.split("@")
        if domain not in ["gmail.com", "yahoo.com", "outlook.com"]:
            score += 15
        if any(char.isdigit() for char in username):
            score += 5
        email_tokens = tokenize_input(email)
        for email in email_tokens:
            if token in sus_dic.get("spi"):
                score += 15
            elif token in sus_dic.get("pii"):
                score += 10
            elif token in sus_dic.get("gen"):
                score += 5
    return score
  
#unit testing
sample = """
URGENT! Verify your bank account now.
Click here:
www.secure-bank-login.xyz at admin1@gmail.com
"""

parsed = parser_input(sample)

print(parsed)

final_score = cal_score(parsed)

print(final_score)