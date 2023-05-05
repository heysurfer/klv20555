#include <cryptopp/md5.h>
#include <cryptopp/hex.h>

template <typename T>
std::string toStr(const T& t) {
	std::ostringstream os;
	os << t;
	return os.str();
}

std::vector<std::string> split(const std::string& s, char delim)
{
	std::vector<std::string> result;
	std::istringstream iss(s);

	for (std::string token; std::getline(iss, token, delim);)
	{
		result.push_back(std::move(token));
	}

	return result;
}

std::string GetMD5CheckSumAsString(const std::string& str)
{
	using byte = unsigned char;
	CryptoPP::Weak1::MD5 md5;
	byte digest[CryptoPP::Weak1::MD5::DIGESTSIZE];
	md5.CalculateDigest(digest, reinterpret_cast<const byte*>(str.c_str()), str.length());
	CryptoPP::HexEncoder encoder;
	std::string encoded;
	encoder.Attach(new CryptoPP::StringSink(encoded));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();
	return encoded;
}

std::string xor_decrypt(uint8_t* encryptedStr, uint8_t pos, uint32_t key)
{
	std::string str;
	std::size_t size = 32;
	str.reserve(32);
	for (std::size_t i = 0; i < size; ++i)
	{
		str.push_back(encryptedStr[i + pos] ^ key);
		key = ((key << 1) | (key >> 31));
	}
	return str;
}

std::string generateKlv(float gameVersion, uint32_t protocol, const std::string& rid, int32_t hash,
                        const std::vector<std::string>& salt)
{
	std::string klv = std::format("{}{}{}{}{}{}{}{}{}",
	                              gameVersion, salt[0], rid.c_str(),
	                              salt[1], salt[2], hash,
	                              salt[3], protocol, salt[4]);
	return GetMD5CheckSumAsString(klv);
}

std::string generateKlvWithAPI(float gameVersion, uint32_t protocol, const std::string& rid, int32_t hash,
                               const std::vector<std::string>& salt, const std::string& method)
{
	std::string klv;
	int lastSaltID = 0;
	const std::vector<std::string> methods = split(method, '+');
	for (const auto& m : methods)
	{
		if (m == "rid")
			klv += rid;
		else if (m == "gameVersion")
			klv += toStr(gameVersion);
		else if (m == "salt")
		{
			klv += salt[lastSaltID];
			++lastSaltID;
		}
		else if (m == "hash")
			klv += toStr(hash);
		else if (m == "protocol")
			klv += toStr(protocol);
	}
	return GetMD5CheckSumAsString(klv);
}

int main()
{
	std::vector<int> _key{-1447198672, -1234183739, -1246037438, -1955177441, 1223948932};
	std::vector<std::string> salt;
	salt.reserve(5);
	uint8_t encryptedStr[]
	{
		0x09, 0x03, 0xF6, 0xB7, 0x3F, 0x73, 0x18, 0x66, 0x99, 0x31,
		0x97, 0x7A, 0xAF, 0x02, 0x57, 0xEA, 0xDF, 0x4D, 0xC2, 0x8D,
		0xBA, 0x80, 0x05, 0xF6, 0xB8, 0x63, 0x66, 0x34, 0x37, 0x64,
		0x6F, 0x2E, 0xA3, 0xBD, 0x72, 0x4E, 0x6C, 0xD3, 0x5A, 0xEB,
		0xD2, 0x54, 0xE1, 0x86, 0x52, 0xFC, 0xA2, 0x53, 0x56, 0xE8,
		0xDA, 0x46, 0x9E, 0x9E, 0x92, 0xD8, 0xBC, 0xD5, 0x04, 0xA8,
		0xAF, 0x0A, 0x40, 0x87, 0x74, 0xB2, 0x68, 0x21, 0x18, 0x33,
		0x99, 0x3E, 0xD4, 0x53, 0xE7, 0xC9, 0x6F, 0xD2, 0x5B, 0xEB,
		0xDB, 0x14, 0x8A, 0xE3, 0xCA, 0x3A, 0xDC, 0x1C, 0xCA, 0x97,
		0xDB, 0xEB, 0x9D, 0x70, 0xF6, 0x10, 0x26, 0x0B, 0x4F, 0x9A,
		0xC8, 0x95, 0xD1, 0xF1, 0xB9, 0x73, 0x15, 0x6F, 0x83, 0x0C,
		0xBB, 0x82, 0x4F, 0xDB, 0xE9, 0x81, 0x5D, 0xFE, 0xF5, 0x4D,
		0x6F, 0x8B, 0x42, 0xD8, 0xA7, 0xB6, 0x31, 0x6A, 0xB0, 0x38,
		0x26, 0x17, 0x72, 0xB1, 0x20, 0x17, 0x2C, 0xA1, 0x1B, 0x76,
		0xBB, 0x7C, 0x08, 0x41, 0xCA, 0xD2, 0xF6, 0xAB, 0x0E, 0x4F,
		0xCA, 0xCD, 0xC2, 0xC2, 0x8F, 0xED, 0x90, 0x33, 0x95, 0x75
	};

	for (auto key : _key)
	{
		uint8_t index = std::distance(_key.begin(), std::find(_key.begin(), _key.end(), key));
		std::string decodedSalt = xor_decrypt(encryptedStr, index * 32, key);
		std::printf("Decrypted Salt %s\n", decodedSalt.c_str());
		salt.push_back(decodedSalt);
	}

	std::printf("Generated Klv %s\n",
	            generateKlv(4.24f, 190, "CD544612B02A2F5D7ADD5366BB4CF1C0", 1054520736, salt).c_str());

	std::printf("Generated Klv %s\n",
		generateKlvWithAPI(4.24f, 190, "CD544612B02A2F5D7ADD5366BB4CF1C0", 1054520736, salt,
			"gameVersion+salt+rid+salt+salt+hash+salt+protocol+salt").c_str());
	/*https://api.surferwallet.net/klv*/
}
