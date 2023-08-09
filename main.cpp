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
	std::vector keys{-1494363509, 10187550, -296521395, 812855768, -273169833};
	std::vector<std::string> salts;
	salts.reserve(5);
	uint8_t encryptedStr[]
	{
		0xB3, 0x24, 0x1C, 0x3C, 0xDB, 0x17, 0xD9, 0xE4, 0x97, 0x2B,
		0xFD, 0x55, 0x0D, 0xBB, 0xD8, 0x47, 0xD8, 0xB9, 0xD1, 0x0B,
		0xEC, 0xDE, 0x44, 0x88, 0xE5, 0xC4, 0x2E, 0xA5, 0x1D, 0x63,
		0x90, 0x74, 0x29, 0x0C, 0x41, 0xC2, 0xD9, 0xF6, 0xE4, 0x64,
		0x64, 0x31, 0x36, 0x62, 0x6A, 0x27, 0x16, 0x7A, 0xAF, 0x57,
		0x5A, 0xB9, 0x83, 0x5A, 0xEF, 0xDC, 0x10, 0x85, 0xFC, 0xAF,
		0x08, 0x5A, 0xA6, 0xEE, 0x7B, 0xA9, 0x04, 0x0B, 0xBB, 0x8C,
		0x1E, 0xCF, 0x88, 0xBA, 0xDF, 0x40, 0xD7, 0xAB, 0xA6, 0x4B,
		0x60, 0xC3, 0x7D, 0xFF, 0x00, 0x0B, 0xEC, 0x89, 0x44, 0xDB,
		0xF6, 0xEF, 0x23, 0x4A, 0x61, 0x94, 0xBA, 0xD2, 0x58, 0xF2,
		0xB6, 0x63, 0x39, 0x79, 0x05, 0x57, 0xA4, 0xB5, 0x64, 0x36,
		0x24, 0x5C, 0x41, 0xD2, 0xF8, 0xA0, 0x07, 0x5F, 0xF5, 0xFB,
		0x50, 0x57, 0xFF, 0xB9, 0x7E, 0x5E, 0x12, 0xDE, 0x32, 0xCE,
		0x68, 0x89, 0x1B, 0xC9, 0x9F, 0xC1, 0xDF, 0xEF, 0x87, 0x4F,
		0xC3, 0xC4, 0xDC, 0xE3, 0x81, 0x5F, 0xE9, 0x8D, 0x1A, 0x9D,
		0xC9, 0xD5, 0xF4, 0xB1, 0x6F, 0x20, 0x41, 0x73, 0xF4, 0x49
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
