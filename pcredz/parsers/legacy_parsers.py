"""
Legacy parser functions from original PCredz
Extracted and adapted for modular structure
"""

import struct
import codecs
import logging
from base64 import b64decode
from datetime import datetime

from ..config import *
from ..utils import parse_ctx1_hash, is_anonymous_ntlm
from ..output import send_webhook_alert



def ParseCTX1Hash(data):
	def decrypt(ct):
		pt = ''
		last = 0
		for i in range(0, len(ct), 4):
			pc = dec_letter(ct[i:i+4], last) 
			pt += pc
			last ^= ord(pc)
		return pt

	def dec_letter(ct, last=0):
		c = (ord(ct[2]) - 1) & 0x0f
		d = (ord(ct[3]) - 1) & 0x0f
		x = c*16+d
		pc = chr(x^last)
		return pc

	x = re.sub('[^A-P]', '', data.upper())
	WriteData("logs/CTX1-Plaintext.txt", Message, Message)
	return str(decrypt(x))

def ParseNTLMHash(data,Challenge):
	PacketLen = len(data)
	if PacketLen > 0:
		SSPIStart = data[:]
		LMhashLen = struct.unpack('<H',data[14:16])[0]
		LMhashOffset = struct.unpack('<H',data[16:18])[0]
		LMHash = codecs.encode(SSPIStart[LMhashOffset:LMhashOffset+LMhashLen],"hex").upper()
		NthashLen = struct.unpack('<H',data[22:24])[0]
		NthashOffset = struct.unpack('<H',data[24:26])[0]

	if NthashLen == 24:
		NtHash = codecs.encode(SSPIStart[NthashOffset:NthashOffset+NthashLen],"hex").upper()
		DomainLen = struct.unpack('<H',data[30:32])[0]
		DomainOffset = struct.unpack('<H',data[32:34])[0]
		Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace(b"\x00",b"")
		UserLen = struct.unpack('<H',data[38:40])[0]
		UserOffset = struct.unpack('<H',data[40:42])[0]
		User = SSPIStart[UserOffset:UserOffset+UserLen].replace(b"\x00",b"")
		writehash = '%s::%s:%s:%s:%s' % (User.decode('latin-1'),Domain.decode('latin-1'), LMHash.decode('latin-1'), NtHash.decode('latin-1'), Challenge.decode('latin-1'))
		WriteData("logs/NTLMv1.txt", writehash, User)
		return "NTLMv1 complete hash is: %s\n"%(writehash), User.decode('latin-1')+"::"+Domain.decode('latin-1')

	if NthashLen > 60:
		NtHash = codecs.encode(SSPIStart[NthashOffset:NthashOffset+NthashLen],"hex").upper()
		DomainLen = struct.unpack('<H',data[30:32])[0]
		DomainOffset = struct.unpack('<H',data[32:34])[0]
		Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace(b"\x00",b"")
		UserLen = struct.unpack('<H',data[38:40])[0]
		UserOffset = struct.unpack('<H',data[40:42])[0]
		User = SSPIStart[UserOffset:UserOffset+UserLen].replace(b"\x00",b"")
		writehash = '%s::%s:%s:%s:%s' % (User.decode('latin-1'),Domain.decode('latin-1'), Challenge.decode('latin-1'), NtHash[:32].decode('latin-1'), NtHash[32:].decode('latin-1'))
		WriteData("logs/NTLMv2.txt", writehash, User)
		return "NTLMv2 complete hash is: %s\n"%(writehash),User.decode('latin-1')+"::"+Domain.decode('latin-1')
	else:
		return False

def ParseMSKerbv5TCP(Data):
	MsgType = Data[19:20]
	EncType = Data[41:42]
	MessageType = Data[30:31]
	if MsgType == b"\x0a" and EncType == b"\x17" and MessageType ==b"\x02":
		if Data[49:53] == b"\xa2\x36\x04\x34" or Data[49:53] == b"\xa2\x35\x04\x33":
			HashLen = struct.unpack('<b',Data[50:51])[0]
			if HashLen == 54:
				Hash = Data[53:105]
				SwitchHash = Hash[16:]+Hash[0:16]
				NameLen = struct.unpack('<b',Data[153:154])[0]
				Name = Data[154:154+NameLen]
				DomainLen = struct.unpack('<b',Data[154+NameLen+3:154+NameLen+4])[0]
				Domain = Data[154+NameLen+4:154+NameLen+4+DomainLen]
				BuildHash = '$krb5pa$23$%s%s%s%s%s' % (Name.decode('latin-1'), "$", Domain.decode('latin-1'), "$dummy$", codecs.encode(SwitchHash,'hex').decode('latin-1'))
				WriteData("logs/MSKerb.txt", BuildHash, Name)
				return 'MSKerb hash found: %s\n'%(BuildHash),"$krb5pa$23$"+Name.decode('latin-1')+"$"+Domain.decode('latin-1')+"$dummy$"
		if Data[42:46] == b"\xa2\x36\x04\x34" or Data[42:46] == b"\xa2\x35\x04\x33":
			HashLen = struct.unpack('<b',Data[45:46])[0]
			Hash = Data[46:46+HashLen]
			SwitchHash = Hash[16:]+Hash[0:16]
			NameLen = struct.unpack('<b',Data[HashLen+94:HashLen+94+1])[0]
			Name = Data[HashLen+95:HashLen+95+NameLen]
			DomainLen = struct.unpack('<b',Data[HashLen+95+NameLen+3:HashLen+95+NameLen+4])[0]
			Domain = Data[HashLen+95+NameLen+4:HashLen+95+NameLen+4+DomainLen]
			BuildHash = '$krb5pa$23$%s%s%s%s%s' % (Name.decode('latin-1'), "$", Domain.decode('latin-1'), "$dummy$", codecs.encode(SwitchHash,'hex').decode('latin-1'))
			WriteData("logs/MSKerb.txt", BuildHash, Name)
			return 'MSKerb hash found: %s\n'%(BuildHash),"$krb5pa$23$"+Name.decode('latin-1')+"$"+Domain.decode('latin-1')+"$dummy$"

		else:
			Hash = Data[48:100]
			SwitchHash = Hash[16:]+Hash[0:16]
			NameLen = struct.unpack('<b',Data[148:149])[0]
			Name = Data[149:149+NameLen]
			DomainLen = struct.unpack('<b',Data[149+NameLen+3:149+NameLen+4])[0]
			Domain = Data[149+NameLen+4:149+NameLen+4+DomainLen]
			BuildHash = '$krb5pa$23$%s%s%s%s%s' % (Name.decode('latin-1'), "$", Domain.decode('latin-1'), "$dummy$", codecs.encode(SwitchHash,'hex').decode('latin-1'))
			WriteData("logs/MSKerb.txt", BuildHash, Name)
			return 'MSKerb hash found: %s\n'%(BuildHash),"$krb5pa$23$"+Name.decode('latin-1')+"$"+Domain.decode('latin-1')+"$dummy$"
	
	else:
		return False

def ParseMSKerbv5UDP(Data):
	MsgType = Data[17:18]
	EncType = Data[39:40]
	if MsgType == b"\x0a" and EncType == b"\x17":
		if Data[40:44] == b"\xa2\x36\x04\x34" or Data[40:44] == b"\xa2\x35\x04\x33":
			HashLen = struct.unpack('<b',Data[41:42])[0]
			if HashLen == 54:
				Hash = Data[44:96]
				SwitchHash = Hash[16:]+Hash[0:16]
				NameLen = struct.unpack('<b',Data[144:145])[0]
				Name = Data[145:145+NameLen]
				DomainLen = struct.unpack('<b',Data[145+NameLen+3:145+NameLen+4])[0]
				Domain = Data[145+NameLen+4:145+NameLen+4+DomainLen]
				BuildHash = '$krb5pa$23$%s%s%s%s%s' % (Name.decode('latin-1'), "$", Domain.decode('latin-1'), "$dummy$", codecs.encode(SwitchHash,'hex').decode('latin-1'))
				WriteData("logs/MSKerb.txt", BuildHash, Name)
				return 'MSKerb hash found: %s\n'%(BuildHash),"$krb5pa$23$"+Name.decode('latin-1')+"$"+Domain.decode('latin-1')+"$dummy$"
			if HashLen == 53:
				Hash = Data[44:95]
				SwitchHash = Hash[16:]+Hash[0:16]
				NameLen = struct.unpack('<b',Data[143:144])[0]
				Name = Data[144:144+NameLen]
				DomainLen = struct.unpack('<b',Data[144+NameLen+3:144+NameLen+4])[0]
				Domain = Data[144+NameLen+4:144+NameLen+4+DomainLen]
				BuildHash = '$krb5pa$23$%s%s%s%s%s' % (Name.decode('latin-1'), "$", Domain.decode('latin-1'), "$dummy$", codecs.encode(SwitchHash,'hex').decode('latin-1'))
				WriteData("logs/MSKerb.txt", BuildHash, Name)
				return 'MSKerb hash found: %s\n'%(BuildHash),"$krb5pa$23$"+Name.decode('latin-1')+"$"+Domain.decode('latin-1')+"$dummy$"

		else:
			HashLen = struct.unpack('<b',Data[48:49])[0]
			Hash = Data[49:49+HashLen]
			SwitchHash = Hash[16:]+Hash[0:16]
			NameLen = struct.unpack('<b',Data[HashLen+97:HashLen+97+1])[0]
			Name = Data[HashLen+98:HashLen+98+NameLen]
			DomainLen = struct.unpack('<b',Data[HashLen+98+NameLen+3:HashLen+98+NameLen+4])[0]
			Domain = Data[HashLen+98+NameLen+4:HashLen+98+NameLen+4+DomainLen]
			BuildHash = '$krb5pa$23$%s%s%s%s%s' % (Name.decode('latin-1'), "$", Domain.decode('latin-1'), "$dummy$", codecs.encode(SwitchHash,'hex').decode('latin-1'))
			WriteData("logs/MSKerb.txt", BuildHash, Name)
			return 'MSKerb hash found: %s\n'%(BuildHash),"$krb5pa$23$"+Name.decode('latin-1')+"$"+Domain.decode('latin-1')+"$dummy$"

	else:
		return False

def ParseSNMP(data):
	SNMPVersion = data[4:5]
	if SNMPVersion == b"\x00":
		StrLen = struct.unpack('<b',data[6:7])[0]
		WriteData("logs/SNMPv1.txt", data[7:7+StrLen].decode('latin-1'), data[7:7+StrLen].decode('latin-1'))
		return 'Found SNMPv1 Community string: %s\n'%(data[7:7+StrLen].decode('latin-1'))
	if data[3:5] == b"\x01\x01":
		StrLen = struct.unpack('<b',data[6:7])[0]
		WriteData("logs/SNMPv2.txt", data[7:7+StrLen].decode('latin-1'), data[7:7+StrLen].decode('latin-1'))
		return 'Found SNMPv2 Community string: %s\n'%(data[7:7+StrLen].decode('latin-1'))

def ParseSMTP(data):
	basic = data[0:len(data)-2]
	OpCode  = [b'HELO',b'EHLO',b'MAIL',b'RCPT',b'SIZE',b'DATA',b'QUIT',b'VRFY',b'EXPN',b'RSET']
	if data[0:4] not in OpCode:
		try:
			Basestr = b64decode(basic)
			if len(Basestr)>1:
				if Basestr.decode('ascii'):
					WriteData("logs/SMTP-Plaintext.txt", Basestr.decode('latin-1'), Basestr.decode('latin-1'))
					return 'SMTP decoded Base64 string: %s\n'%(Basestr.decode('latin-1'))
		except:
			pass

def ParseSqlClearTxtPwd(Pwd):
	Pwd = Pwd.decode('latin-1')
	Pwd = map(ord,Pwd.replace('\xa5',''))
	Pw = b''
	for x in Pwd:
		Pw += codecs.decode(hex(x ^ 0xa5)[::-1][:2].replace("x", "0"), 'hex')
	return Pw.decode('latin-1')

def ParseMSSQLPlainText(data):
	UsernameOffset = struct.unpack('<h',data[48:50])[0]
	PwdOffset = struct.unpack('<h',data[52:54])[0]
	AppOffset = struct.unpack('<h',data[56:58])[0]
	PwdLen = AppOffset-PwdOffset
	UsernameLen = PwdOffset-UsernameOffset
	PwdStr = ParseSqlClearTxtPwd(data[8+PwdOffset:8+PwdOffset+PwdLen])
	UserName = data[8+UsernameOffset:8+UsernameOffset+UsernameLen].decode('utf-16le')
	WriteData("logs/MSSQL-Plaintext.txt", "MSSQL Username: %s Password: %s"%(UserName, PwdStr), UserName)
	return "MSSQL Username: %s Password: %s\n"%(UserName, PwdStr)