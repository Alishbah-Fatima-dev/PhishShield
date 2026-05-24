import re

def clean_items(list1):
    emp_list=[]
    for r in list1 :
        cln=r.strip()
        emp_list.append(cln)
    return emp_list

def parser_input(text):
    text=text.lower()
    emails= re.findall(r'\S+@\S+',text)
    urls= re.findall(r"http://''S+ | https://''S+ | www\.\S+\.\S+",text)
    emails = clean_items(emails)
    urls = clean_items(urls)
    parsed_data= {
        "emails": emails,
        "urls": urls,
        "text": text}
    return parsed_data

print(parser_input("Contact me at test@gmail.com "))#temp
print(parser_input("this is UET from www.uetofficial.edu"))#temp
sus_words=["verify","account","password","otp","click","urgent","now","alert"]

feature_weights={ }
def cal_score(parsed_data):
    score=0
    token="now"#temporary 
    tok=0
    for i in sus_words:
        if token==i:
            tok=1
            print("token exists.")
            break
    if tok==0:
        print("token not found")
cal_score({})

     