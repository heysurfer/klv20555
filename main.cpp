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
	std::vector keys{-91863646, -969031837, 1103616536, 943360009, -1982213226};
	std::vector<std::string> salts;
	salts.reserve(5);
	uint8_t encryptedStr[]
	{
		0x9A, 0x76, 0xB9, 0x76, 0x4E, 0x3C, 0x8E, 0x4A, 0xCB, 0x93,
		0x8C, 0xB6, 0xCB, 0x36, 0xC2, 0x72, 0xB3, 0x6E, 0x7F, 0x57,
		0x55, 0xAC, 0xA1, 0x43, 0x72, 0xEA, 0x72, 0x1C, 0x6F, 0x86,
		0x5A, 0xE0, 0x54, 0xF7, 0xB6, 0x2C, 0x05, 0x4E, 0x95, 0x87,
		0xA2, 0xBC, 0x2C, 0x57, 0x00, 0xF3, 0xBF, 0x29, 0x09, 0x1A,
		0xC1, 0x8F, 0xEF, 0x83, 0x5C, 0xBA, 0xDC, 0x1D, 0xCD, 0xCC,
		0xCF, 0xD5, 0xB9, 0xD0, 0x2E, 0x02, 0x52, 0xA6, 0xE1, 0x39,
		0x75, 0x18, 0x27, 0xE5, 0x61, 0x3C, 0x2E, 0x59, 0x43, 0x81,
		0xF4, 0xEA, 0x2F, 0x5A, 0x4A, 0x9E, 0xC6, 0xDC, 0xEF, 0x8D,
		0x5B, 0xB5, 0x96, 0x20, 0xB4, 0x3E, 0x6B, 0x70, 0x1C, 0x7A,
		0xA6, 0x42, 0x7B, 0xFD, 0x0D, 0x47, 0x85, 0xF7, 0xE0, 0x3F,
		0x36, 0x78, 0x08, 0x41, 0xDE, 0xED, 0x9C, 0x68, 0x9B, 0x27,
		0xE9, 0x24, 0x18, 0x77, 0xE3, 0x64, 0x66, 0x36, 0xF3, 0x4C,
		0x6D, 0x82, 0x0D, 0xE5, 0xC6, 0x72, 0xB9, 0x23, 0x1E, 0x7C,
		0xA5, 0x09, 0x47, 0xD4, 0xEF, 0x83, 0x51, 0xFD, 0xFB, 0x5F,
		0x4D, 0xDD, 0xE5, 0x92, 0x28, 0xAE, 0x5D, 0x4B, 0x84, 0xA9
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
	            generateKlv(4.38f, 200, "0182E268D08AB45702A841A172170E12", 1431658473, salts).c_str());
}
