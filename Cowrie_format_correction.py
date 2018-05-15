#cowrie_file = open('G:\Cyber Security\cybox and stix\logs\cowrie.json', mode='at', encoding='utf-8')

f = open('C:\\Users\DELL\Desktop\cowrie mam logs.json','r+')
lines = f.readlines() # read old content
f.seek(0) # go back to the beginning of the file
f.write('[') # write new content at the beginning
count=0

for line in lines: # write old content after new
    if count!=0 :
        f.writelines(',')
    count=count+1
    f.write(line)
f.write(']')
f.close()

#cowrie_file.seek(0)
#cowrie_file.write('[')
#cowrie_file.close()
#print(cowrie_file.read())