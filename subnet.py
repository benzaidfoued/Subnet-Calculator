
print ("######################## Benzaid Foued Subnet Calculator V1.0#################################")
print("###############################################################################################")



user = input(" Please Enter a Valid IP Adressse...")
ip = user.split(".")

if (len(ip) == 4) and (1 <= int(ip[0])  <=223) and (int(ip[0]) != 127 ) and (int(ip[0]) != 169 or int(ip[1]) !=254 ) and ( 0 <= int(ip[1]) <= 255 ) and ( 0 <= int(ip[2]) <= 255 ) and ( 0 <= int(ip[3]) <= 255 ):
   print(" this is a Valid IP Address ...") 
   #break 
else:
    print(" not a Valid IP Adress...")   

default = [255, 254, 252, 248, 240, 224, 192, 128, 0]   

cmask = input(" Please Enter a Valid Subnet Mask...")
b = cmask.split(".")

if (len(b) == 4) and  (int(b[0]) == 255) and (int(b[1]) in default) and (int(b[2]) in default) and (int(b[3]) in default) and (int(b[0]) >= int(b[1]) >= int(b[2]) >= int(b[3])):
    print (" this is a correct  Mask")
else:
    print(" Not a Valid Mask try Again...") 

binary_added = []
z = cmask.split(".")
for octects in range(0, len(b)):
    binary = bin(int(z[octects] )).split("b")[1]  
    if len(binary) == 8:
        binary_added.append(binary)

    elif len(binary) < 8:
        final_binary = binary.zfill(8)
        binary_added.append(final_binary)   

subnet_mask = "".join(binary_added)
#print(subnet_mask)
Num_zero = subnet_mask.count("0")
Num_one = 32 - Num_zero
Num_hosts = abs(2 ** Num_zero - 2)
#print (Num_one)
#print(Num_zero)
#print(Num_hosts)

wild_mask = []

for wild in b:
     real_wild = 255 - int(wild)
     wild_mask.append(str(real_wild))

#print(wild_mask)
real_wild_mask = ".".join(wild_mask)       
print(real_wild_mask)     
    
ip_add = []
ik = user.split(".")

for koko in range(0 , len(ik)):
    demi_ip = bin(int((ik)[koko])).split("b")[1]
    if len(demi_ip) == 8:
        ip_add.append(demi_ip) 
    elif len(demi_ip) < 8:
        foufou = demi_ip.zfill(8)
        ip_add.append(foufou)

ip_binary = "".join(ip_add)
print(ip_binary)    

# Network and Broadcat Addresses fi el binary

Network_address = ip_binary[:(Num_one)] + "0" * Num_zero
Broadcast_address = ip_binary[:(Num_one)]  + "1" *  Num_zero

print(Network_address)

##################### hnaya nahsseb network address men les bits lel octets###########
ip_octets = []
for octet in range(0,len(Network_address), 8):
    ip_octet = Network_address[octet:octet+8]
    ip_octets.append(ip_octet)
print(ip_octets)    

net_ip_address = []

for each_octest in ip_octets:
    net_ip_address.append(str(int(each_octest,2)))

print(net_ip_address)    

real_network_address = ".".join(net_ip_address)
print(real_network_address)
####################### hnaya nahsseb brodcast@ men broadcast@ eli hsebtha bel bits############
baddr = []
for octet in range(0,len(Broadcast_address),8):
    boctet = Broadcast_address[octet:octet+8]
    baddr.append(boctet)
print(baddr)   

bdr = []
for wow in baddr:
    bdr.append(str(int(wow,2)))
print(bdr)

real_broadcast_address = ".".join(bdr)
print(real_broadcast_address)

print ("\n")

print ("\n")
print ("Network address is: {} ".format(real_network_address))
print ("Broadcast address is: {}".format(real_broadcast_address))
print ("Number of valid hosts per subnet: {}".format(Num_hosts))
print ("Wildcard mask: {} ".format(real_wild_mask))
print ("Subnet Mask bits: {} ".format(Num_one))
print ("\n")