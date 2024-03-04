#pragma once
#include <iostream>
#include <cstring>
#include <string_view>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

const char *hex_byte[256] = {
		"00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
		"10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
		"20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
		"30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
		"40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
		"50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
		"60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
		"70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
		"80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
		"90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
		"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
		"b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
		"c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
		"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db", "dc", "dd", "de", "df",
		"e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
		"f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff"
};


class SHA
{
private:
	EVP_MD_CTX *hash_ctx_;
	const EVP_MD *hash_ptr_;

	unsigned char buffer_[BUFSIZ];
	unsigned int buffer_len_ = 0;

	std::string buff_out_;

	const std::string sha_name_;


	bool Init()
	{
		hash_ptr_ = EVP_get_digestbyname(sha_name_.c_str());
		if (!hash_ptr_)
		{
			std::cerr << "error EVP_get_digestbyname" << std::endl;
			ERR_print_errors_fp(stderr);
			return false;
		}

		hash_ctx_ = EVP_MD_CTX_new();
		if (!hash_ctx_)
		{
			std::cerr << "error EVP_MD_CTX_new" << std::endl;
			ERR_print_errors_fp(stderr);
			return false;
		}

		if (EVP_DigestInit_ex(hash_ctx_, hash_ptr_, nullptr) != 1)
		{
			std::cerr << "error EVP_DigestInit_ex" << std::endl;
			ERR_print_errors_fp(stderr);
			return false;
		}

		return true;
	}

	void Reset()
	{
		EVP_MD_CTX_free(hash_ctx_);
		hash_ctx_ = nullptr;
		hash_ptr_ = nullptr;
	}

public:
	explicit SHA(const char *sha_name = "SHA1")
	: sha_name_(sha_name)
	, buffer_{}
	{
		hash_ctx_ = nullptr;
		hash_ptr_ = nullptr;
	}

	~SHA()
	{
		Reset();
	}

	std::string_view GetHash(std::string_view data)
	{
		if (!Init())
		{
			return {};
		}

		auto len_copy = 0;
		buffer_len_ = 0;
		do
		{
			len_copy = std::min(BUFSIZ, (int)(data.length() - buffer_len_));
			memcpy(buffer_, &data[buffer_len_], len_copy);
			if (EVP_DigestUpdate(hash_ctx_, buffer_, len_copy) != 1)
			{
				std::cerr << "error EVP_DigestUpdate" << std::endl;
				ERR_print_errors_fp(stderr);
				return {};
			}
			buffer_len_ += len_copy;
		}
		while (len_copy == BUFSIZ);

		if (EVP_DigestFinal_ex(hash_ctx_, buffer_, &buffer_len_) != 1)
		{
			std::cerr << "error EVP_DigestFinal_ex" << std::endl;
			ERR_print_errors_fp(stderr);
			return {};
		}

		size_t buf_tmp_len = buffer_len_ * 2;
		char buf_tmp[buf_tmp_len];

		for (int i = 0; i < buffer_len_; i++)
			*(int16_t *)(buf_tmp + i * 2) = *(int16_t *)hex_byte[buffer_[i]];

		buff_out_ = std::string(buf_tmp, buf_tmp_len);
		Reset();
		return buff_out_;
	}
};



bool SHA1_Test()
{
	std::string test1 = "qwerty";
	std::string res1 = "b1b3773a05c0ed0176787a4f1574ff0075f7521e";

	std::string test2 = "user-agent";
	std::string res2 = "0704546d55e8c7e75ae4e1760192e86b4a221f7c";

	std::string test3 = "Mozilla/5.0 (X11; U; Linux i686; ru; rv:1.9b5) Gecko/2008050509 Firefox/3.0b5";
	std::string res3 = "6b05fff607fe0a1f8791142ec26955069ea3ad06";

	SHA sha("SHA1");

	std::string_view res;
	res = sha.GetHash(test1);
	if (res != res1)
	{
		std::cout << "Error test 1 str:" << test1 << std::endl;
		std::cout << "etl hash:" << res1 << std::endl;
		std::cout << "res hash:" << res << std::endl;
		return false;
	}

	res = sha.GetHash(test2);
	if (res != res2)
	{
		std::cout << "Error test 2 str:" << test2 << std::endl;
		std::cout << "etl hash:" << res2 << std::endl;
		std::cout << "res hash:" << res << std::endl;
		return false;
	}

	res = sha.GetHash(test3);
	if (res != res3)
	{
		std::cout << "Error test 3 str:" << test3 << std::endl;
		std::cout << "etl hash:" << res3 << std::endl;
		std::cout << "res hash:" << res << std::endl;
		return false;
	}

	return true;
}

bool SHA256_Test()
{
	std::string test1 = "qwerty";
	std::string res1 = "65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5";

	std::string test2 = "user-agent";
	std::string res2 = "a510e50665127ebf4514975babcac22aff4d1b9a82edf378305cd2bfede4ec83";

	std::string test3 = "Mozilla/5.0 (X11; U; Linux i686; ru; rv:1.9b5) Gecko/2008050509 Firefox/3.0b5";
	std::string res3 = "05ff2162290d87f6a29df659652acf10f6488f55ca50bec7970b245528e8a5ad";

	SHA sha("SHA256");

	std::string_view res;
	res = sha.GetHash(test1);
	if (res != res1)
	{
		std::cout << "Error test 1 str:" << test1 << std::endl;
		std::cout << "etl hash:" << res1 << std::endl;
		std::cout << "res hash:" << res << std::endl;
		return false;
	}

	res = sha.GetHash(test2);
	if (res != res2)
	{
		std::cout << "Error test 2 str:" << test2 << std::endl;
		std::cout << "etl hash:" << res2 << std::endl;
		std::cout << "res hash:" << res << std::endl;
		return false;
	}

	res = sha.GetHash(test3);
	if (res != res3)
	{
		std::cout << "Error test 3 str:" << test3 << std::endl;
		std::cout << "etl hash:" << res3 << std::endl;
		std::cout << "res hash:" << res << std::endl;
		return false;
	}

	return true;
}

bool SHA512_Test()
{
	std::string test1 = "qwerty";
	std::string res1 = "0dd3e512642c97ca3f747f9a76e374fbda73f9292823c0313be9d78add7cdd8f72235af0c553dd26797e78e1854edee0ae002f8aba074b066dfce1af114e32f8";

	std::string test2 = "user-agent";
	std::string res2 = "caa0e815a7d7a449503c1c3a054bd59403d09eff619ac87de0445c3aeb92c06835116d3562c54707bba638b1c6fc97011d35c79637dddcfc0b508d5afe5b3615";

	std::string test3 = "Mozilla/5.0 (X11; U; Linux i686; ru; rv:1.9b5) Gecko/2008050509 Firefox/3.0b5";
	std::string res3 = "087747c260d9b77f7ec3a0c82f5a37862dc98f9b051ad8b6a351d7ae5fbc1babd0f824df94611abc56ac70592603a991cec7e158a7862083694fe20ace9e3d61";

	SHA sha("SHA512");

	std::string_view res;
	res = sha.GetHash(test1);
	if (res != res1)
	{
		std::cout << "Error test 1 str:" << test1 << std::endl;
		std::cout << "etl hash:" << res1 << std::endl;
		std::cout << "res hash:" << res << std::endl;
		return false;
	}

	res = sha.GetHash(test2);
	if (res != res2)
	{
		std::cout << "Error test 2 str:" << test2 << std::endl;
		std::cout << "etl hash:" << res2 << std::endl;
		std::cout << "res hash:" << res << std::endl;
		return false;
	}

	res = sha.GetHash(test3);
	if (res != res3)
	{
		std::cout << "Error test 3 str:" << test3 << std::endl;
		std::cout << "etl hash:" << res3 << std::endl;
		std::cout << "res hash:" << res << std::endl;
		return false;
	}

	return true;
}
