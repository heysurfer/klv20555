#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>

template <typename T>
std::string toStr(const T& t)
{
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

std::string sha256(const std::string& text)
{
	CryptoPP::SHA256 hash;
	std::string digest;

	CryptoPP::StringSource(text, true,
	                       new CryptoPP::HashFilter(hash,
	                                                new CryptoPP::HexEncoder(
		                                                new CryptoPP::StringSink(digest)
	                                                )
	                       )
	);

	return digest;
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
	str.reserve(size);

	for (std::size_t i = 0; i < size; ++i)
	{
		str.push_back(encryptedStr[i + pos] ^ key);
		key = ((key << 1) | (key >> 31));
	}
	return str;
}

std::string generateKlv(float gameVersion, uint32_t protocol, const std::string& rid, int32_t hash,
                        const std::vector<std::string>& salts)
{
	std::string klv = GetMD5CheckSumAsString(GetMD5CheckSumAsString(std::to_string(gameVersion)));
	klv.append((salts[0]));
	klv.append(GetMD5CheckSumAsString(GetMD5CheckSumAsString(GetMD5CheckSumAsString(std::to_string(protocol)))));
	klv.append((salts[1]));
	klv.append((salts[2]));
	klv.append(GetMD5CheckSumAsString(GetMD5CheckSumAsString(rid)));
	klv.append((salts[3]));
	klv.append(GetMD5CheckSumAsString(GetMD5CheckSumAsString(std::to_string(hash))));
	klv.append((salts[4]));

	return GetMD5CheckSumAsString(klv);
}

int main()
{
	std::vector keys{1924589147, -453648294, 2068226457, 1868649288, -970678841};
	std::vector<std::string> salts;
	salts.reserve(5);
	uint8_t encryptedStr[]
	{
		0x63, 0x85, 0x5F, 0xBA, 0xD6, 0x0D, 0xEC, 0x8E, 0x43, 0x83,
		0xAC, 0xF7, 0x48, 0x30, 0xCE, 0x6A, 0x83, 0x0F, 0xBD, 0xD2,
		0x5F, 0xB8, 0x89, 0x12, 0xD1, 0xAD, 0xFD, 0x03, 0x50, 0xF9,
		0xA4, 0x1C, 0x6D, 0x85, 0x52, 0xE5, 0x97, 0x6A, 0xDD, 0x16,
		0x80, 0xF9, 0xA7, 0x41, 0x2C, 0xAA, 0x0D, 0x4D, 0xC1, 0x8A,
		0xE0, 0xCD, 0x6A, 0x88, 0x4B, 0x95, 0x83, 0xA3, 0xB1, 0x35,
		0x3C, 0x32, 0x77, 0x4C, 0xAF, 0x00, 0x56, 0xAF, 0xF2, 0x1E,
		0x3B, 0x85, 0x1D, 0x90, 0x8B, 0xE8, 0x86, 0x09, 0xE3, 0xC1,
		0x75, 0xE8, 0x2A, 0x51, 0x5D, 0xB1, 0x98, 0x61, 0x94, 0x7A,
		0xB5, 0x69, 0x2E, 0x50, 0x54, 0xFE, 0x2A, 0xF2, 0x19, 0x70,
		0xB3, 0x68, 0x2E, 0x56, 0x5A, 0xE9, 0xD8, 0x4D, 0x95, 0xD4,
		0xE0, 0xD5, 0x53, 0xF6, 0xB1, 0x33, 0x21, 0x13, 0x6D, 0xCA,
		0x32, 0x92, 0x75, 0xAD, 0x57, 0x0C, 0xB6, 0x96, 0xA2, 0xEE,
		0x28, 0x08, 0x19, 0xCC, 0x95, 0xD5, 0xF6, 0xBC, 0x21, 0x03,
		0x5A, 0xF6, 0xB8, 0x2A, 0x12, 0x79, 0xA4, 0x17, 0x2F, 0xF6,
		0x1E, 0x7A, 0xAB, 0x0E, 0x11, 0xDC, 0xB8, 0x81, 0x10, 0x81
	};
	static_assert(sizeof(encryptedStr) >= 160, "Encrypted string size must be at least 160");

	for (auto key : keys)
	{
		int index = std::distance(keys.begin(), std::find(keys.begin(), keys.end(), key));
		std::string decSalt = xor_decrypt(encryptedStr, index * 32, key);
		std::printf("%i.Salt : %s\n", index, decSalt.c_str());
		salts.push_back(decSalt);
	}

	std::printf("Generated Klv %s\n",
	            generateKlv(4.34f, 191, "0182E268D08AB45702A841A172170E12", 1431658473, salts).c_str());
}
