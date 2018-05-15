
import json
import re
from cybox.core import Observables
from cybox.objects.network_connection_object import NetworkConnection
from cybox.objects.socket_address_object import SocketAddress
from cybox.objects.port_object import Port
from cybox.common.object_properties import CustomProperties, Property
from cybox.objects.user_account_object import UserAccount
from cybox.objects.account_object import Authentication
from cybox.objects.custom_object import Custom
from cybox.objects.file_object import File
from cybox.common.hashes import Hash,HashList


def create_hash(hashvalue,hashesList,message):
    has=HashList()
    hsh=Hash()
    for h in hashesList:
        if re.search(h.upper(), message.upper()):
            h = h.replace("-", "")
            hsh.type_ = h
    hsh.simple_hash_value=hashvalue
    has.hashes=hsh
    return has


def create_port(prtvalue):
    prt=Port()
    prt.port_value=prtvalue
    return prt


def create_socket_address(ip,prt):
    sock=SocketAddress()
    sock.ip_address=ip
    sock.port=create_port(prt)
    return sock


def create_authentictication(pasword):
    auth = Authentication()
    auth.authentication_type="Password"
    auth.authentication_data=pasword
    return auth


def create_custom_properties(object,propertyName,propertyValue):
    prop = Property()
    prop.name = propertyName
    prop.value = str(propertyValue)
    object.custom_properties.append(prop)


def create_file_observable(ct,bol):
    obj=File()
    obj.file_path=d[ct]['ttylog']
    obj.accessed_time=d[ct]['timestamp']
    obj.custom_properties = CustomProperties()
    if bol == False:
        obj.size_in_bytes=d[ct]['size']
        create_custom_properties(obj, "session_Duration", d[ct]['duration'])
    create_custom_properties(obj, "Event_Name", d[ct]['eventid'])
    create_custom_properties(obj, "Message", d[ct]['message'])
    create_custom_properties(obj, "Service", d[ct]['system'])
    create_custom_properties(obj, "Host", d[ct]['sensor'])
    create_custom_properties(obj, "Source_IP_Address", d[ct]['src_ip'])

    return obj


def create_download_upload_file_observable(ct,hashList,bol):
    obj=File()
    obj.custom_properties = CustomProperties()
    #obj.file_path=d[ct]['url']
    try:
        obj.hashes = create_hash(d[ct]['shasum'], hashList, d[ct]['message'])
        create_custom_properties(obj, "OutFile", d[ct]['outfile'])
        create_custom_properties(obj, "Service", d[ct]['system'])
    except:
        print()
    finally:
        if bol==True:
            #print(bol)
            create_custom_properties(obj, "URL", d[ct]['url'])
            #obj.hashes=create_hash(d[ct]['shasum'],hashList,d[ct]['message'])
            #create_custom_properties(obj, "OutFile", d[ct]['outfile'])

        obj.accessed_time=d[ct]['timestamp']
        #create_custom_properties(obj, "URL", d[ct]['url'])
        create_custom_properties(obj, "Event_Name", d[ct]['eventid'])
        create_custom_properties(obj, "Message", d[ct]['message'])
        create_custom_properties(obj, "Host", d[ct]['sensor'])
        create_custom_properties(obj, "Source_IP_Address", d[ct]['src_ip'])
    return obj




def create_user_account_observable(ct):
    obj=UserAccount()
    obj.username=d[ct]['username']
    obj.last_accessed_time= d[ct]['timestamp']
    obj.authentication=create_authentictication(d[ct]['password'])
    obj.custom_properties=CustomProperties()
    create_custom_properties(obj, "Event_Name", d[ct]['eventid'])
    create_custom_properties(obj, "Message", d[ct]['message'])
    create_custom_properties(obj, "Service", d[ct]['system'])
    create_custom_properties(obj, "Host", d[ct]['sensor'])
    create_custom_properties(obj, "Source_IP_Address", d[ct]['src_ip'])
    return obj


def create_network_connection_closed_observable(ct):
    obj = NetworkConnection()
    obj.creation_time = d[ct]['timestamp']
    sock = SocketAddress()
    sock.ip_address = d[ct]['src_ip']
    obj.source_socket_address=sock
    obj.custom_properties = CustomProperties()
    create_custom_properties(obj, "Event_Name", d[ct]['eventid'])
    create_custom_properties(obj, "Message", d[ct]['message'])
    create_custom_properties(obj, "Service", d[ct]['system'])
    create_custom_properties(obj, "Host", d[ct]['sensor'])
    create_custom_properties(obj, "session_Duration",d[ct]['duration'])
    return obj


def create_command_observable(ct,bol):
    obj=Custom()
    obj.custom_name='InputCommandObject'
    obj.custom_properties=CustomProperties()
    create_custom_properties(obj, "Event_Name", d[ct]['eventid'])
    create_custom_properties(obj, "Message", d[ct]['message'])
    create_custom_properties(obj, "Service", d[ct]['system'])
    create_custom_properties(obj, "Host", d[ct]['sensor'])
    create_custom_properties(obj, "Timestamp", d[ct]['timestamp'])
    if bol==True:
        create_custom_properties(obj, "Input_Command", d[ct]['input'])
    return obj


def create_network_connection_observable (ct):
    obj = NetworkConnection()
    obj.creation_time = d[ct]['timestamp']
    obj.layer7_protocol = d[ct]['protocol']

    # src_info
    obj.source_socket_address =create_socket_address( d[ct]['src_ip'], d[ct]['src_port'])

    # dst_info
    obj.destination_socket_address = create_socket_address(d[ct]['dst_ip'], d[ct]['dst_port'])

    #create_custom_properties
    obj.custom_properties = CustomProperties()
    create_custom_properties(obj,"Event_Name",d[ct]['eventid'])
    create_custom_properties(obj,"Message", d[ct]['message'])
    create_custom_properties(obj,"Service", d[ct]['system'])
    create_custom_properties(obj, "Host", d[ct]['sensor'])
    return obj


with open('G:\Cyber Security\cybox and stix\logs\cowrie_logs.json',encoding='utf-8') as json_data:
    d = json.load(json_data)
    Obs = Observables()
    #print(d[2])
    #mapping starts
    count = 0
    hashes={'MD-5','MD-6','SHA-1','SHA-224','SHA-256','SHA-224','SHA-384', 'SHA-512','SSD-EEP'
            'MD5','MD6','SHA1','SHA224','SHA256','SHA224','SHA384','SHA512','SSDEEP'}

for a in d:
    Bol = True
    if d[count]['eventid'] == 'cowrie.session.connect' :
       Obs.add(create_network_connection_observable(count))
    if d[count]['eventid']== 'cowrie.login.failed' or d[count] ['eventid']== 'cowrie.login.success':
        Obs.add(create_user_account_observable(count))
    if d[count]['eventid'] == 'cowrie.session.closed' :
       Obs.add(create_network_connection_closed_observable(count))
    if d[count]['eventid'] == 'cowrie.command.input' :
       Bol=True
       Obs.add(create_command_observable(count,Bol))
    if d[count]['eventid']== 'cowrie.command.failed':
       Bol=False
       Obs.add(create_command_observable(count,Bol))
    if d[count]['eventid'] == 'cowrie.log.open':
       Bol=True
       Obs.add(create_file_observable(count,Bol))
    if d[count]['eventid'] == 'cowrie.log.closed':
       Bol = False
       Obs.add(create_file_observable(count, Bol))
    if d[count]['eventid'] == 'cowrie.session.file_download' or d[count]['eventid'] == 'cowrie.session.file_upload':
       if d[count]['eventid'] == 'cowrie.session.file_upload':
           Bol = False
       Obs.add(create_download_upload_file_observable(count,hashes,Bol))
    if d[count]['eventid'] == 'cowrie.session.file_download.failed':
       Bol=False
       Obs.add(create_download_upload_file_observable(count,hashes,Bol))
    count=count+1

    #writing to files
f = open('C:\\Users\DELL\Desktop\cowrie_to_cybox.json', 'w')
#f.write('<?xml version="1."?>')
f.write(Obs.to_json())
f.close()

