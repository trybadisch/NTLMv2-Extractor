import pyshark
import sys

if len(sys.argv) != 3:
    print("[!] Usage: ./"+sys.argv[0]+" pcap_file output_file")
    sys.exit()

filename = sys.argv[1]
output = sys.argv[2]
cap = pyshark.FileCapture(filename, display_filter='http', keep_packets=False)
hashes = []

for packet in cap:
    packet = packet.http
    try:
        if hasattr(packet, 'ntlmssp_messagetype'):
            # NTLM server challenge
            if packet.ntlmssp_messagetype == "0x00000002":
                challenge = packet.ntlmssp_ntlmserverchallenge.replace(':', '')
                request = packet.request_in
            
            # NTLM client response (tracked by request)
            if packet.ntlmssp_messagetype == "0x00000003" and packet.prev_request_in == request:
                username = packet.ntlmssp_auth_username
                domain = packet.ntlmssp_auth_domain
                hmac = packet.ntlmssp_ntlmv2_response_ntproofstr.replace(':', '')
                response = packet.ntlmssp_ntlmv2_response.replace(':', '')

                hash = username+'::'+domain+':'+challenge+':'+hmac+':'+response
                print('[+] '+domain+'\\'+username+' hash found.')
                hashes.append(hash)

                request = 0
        
    except Exception as e:
        print(e)
        pass

hashes = set(hashes)

print('\n[*] '+str(len(hashes))+' hashes found:')
with open(output, 'w') as file:
    for hash in hashes:
        file.write(hash+'\n')
        print(hash)