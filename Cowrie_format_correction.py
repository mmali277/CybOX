

#your file path comes here:
f = open('C:\\Users\DELL\Desktop\cowrie_logs.json','r+')
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

