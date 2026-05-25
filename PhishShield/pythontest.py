print("hello")
age=9
if age>10:
    print("adult with age being",age)
else:
    print("not an adult ",age)
print(5+7)
print(input("enter a number : "))
name="bin"
print(name)
print (age + 4)
print(3**6)
# if elif elif else 
for i in range(2,6,2):# last 2 is the step or incremental value
    print("hello")
string= "security"
for char in string:
    print(char)
a=0
while a<5:
    print(a)
    a+=2
def add(a,b):
    return a+b 
print(add(2,5))
print ( type(6))
list1=["bin","shin","glin"]
for list in list1:
    print(list)
list1.append("frin")
print(list1)
print(list1[2])
print(len(list1))
student={
    "name":"lisha",
    "age": 18
}
print(student["name"])
print(student)
for key,value in student.items():
    print(value)
stone="turq"
print(stone.replace("turq","ruby"))
name="lisha"
print(f"hello {name}")
# with open("text.txt","w") as file:
 # file.write("hello")
 # with open ("text.txt","r") as file:
  # content = file.read() then print(content)
# multi line comment 
'''hello 
this is 
world'''
print("this is pythontest file and\n we are practicing")