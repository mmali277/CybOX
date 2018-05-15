# CybOX
Python scripts of Cybox mapping with honeypots.
Following python packages and libraries are needed 

        cybox 2.1.0.17 
        lxml 4.2.1 
        python-dateutil 2.7.2 
        setuptools 39.0.1

Cowire mapping: It maps logs file of Cowrie which has json format. if Json files has some issues while reading through "cowrie_to_stix.py", then you have to use "Cowrie_format_correction.py". Other wise no need for it.

# How to run

        1.) Write your input file path (on line 163 of cowrie_to_stix.py) that must be ".json" file.
        
        2.) Write yout out file path (on line 202 of cowrie_to_stix.py) with two options:
        
              2a.) If you want output in json format, your output file should end with ".json" extension. e.g output.json
                  and mode should be set to 'w'. e.g 
                  f = open('C:\\Users\DELL\Desktop\output.json', 'w')
                  
              2b.)If you want output in xml format, your output file should end with ".xml" extension. e.g output.xml
                  and mode should be set to 'wb'. e.g 
                  f = open('C:\\Users\DELL\Desktop\output.xml', 'wb')
        3.) That's it, you are all set.   

