#include <windows.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <iostream>

#include <string>
#include <stdexcept>
#include <vector>

#include "tweetnacl.h"
#include "icr_randombytes.h"

#pragma pack(push, 1)
struct BLACKLIST_FILE_HEADER
{
	unsigned char nonce[crypto_box_NONCEBYTES];
	unsigned char sender_encryption_public_key[crypto_box_PUBLICKEYBYTES];
	std::uint32_t ciphertext_size;
};
#pragma pack(pop)

// Build payload [path_size][path_bytes]...[path_size][path_bytes]
// Paths are assumed to be UTF-8 encoded byte strings.
static std::vector<unsigned char> build_payload_from_paths(
	const std::vector<std::string>& path_list)
{
	std::vector<unsigned char> payload_buffer;

	for (const std::string& path_string : path_list)
	{
		std::uint32_t path_length = static_cast<std::uint32_t>(path_string.size());
		const std::uint32_t path_length_with_terminator = path_length + 1;

		// Append 4 bytes of path_length
		payload_buffer.insert(
			payload_buffer.end(),
			reinterpret_cast<const unsigned char*>(&path_length_with_terminator),
			reinterpret_cast<const unsigned char*>(&path_length_with_terminator) + sizeof(path_length_with_terminator));

		// Append actual path bytes (UTF-8)
		payload_buffer.insert(
			payload_buffer.end(),
			reinterpret_cast<const unsigned char*>(path_string.data()),
			reinterpret_cast<const unsigned char*>(path_string.data()) + path_length);

		payload_buffer.push_back('\0');
	}

	return payload_buffer;
}

// Sign payload
// crypto_sign output format: [signature (crypto_sign_BYTES)][message]
static std::vector<unsigned char> sign_payload(
	const std::vector<unsigned char>& payload_buffer,
	const unsigned char signer_secret_key[crypto_sign_SECRETKEYBYTES],
	std::uint64_t& signed_message_length_out)
{
	std::uint64_t payload_length = static_cast<std::uint64_t>(payload_buffer.size());

	std::vector<unsigned char> signed_message_buffer(payload_length + crypto_sign_BYTES);

	if (crypto_sign(signed_message_buffer.data(),
		&signed_message_length_out,
		payload_buffer.data(),
		payload_length,
		signer_secret_key) != 0)
	{
		throw std::runtime_error("crypto_sign failed");
	}

	signed_message_buffer.resize(static_cast<std::size_t>(signed_message_length_out));
	return signed_message_buffer;
}

// The plaintext blob is still not encrypted, but it embeds signature-related
// information. The format is:
//
//   [signer_public_key (crypto_sign_PUBLICKEYBYTES bytes)]
//   [signed_message_size (UINT32, little-endian)]
//   [signed_message (signature + payload, signed_message_size bytes)]
//
// The kernel will parse this blob, then call crypto_sign_open() to verify the
// signature and recover the original payload (the list of paths).
static std::vector<unsigned char> build_plaintext_blob(
	const unsigned char signer_public_key[crypto_sign_PUBLICKEYBYTES],
	const std::vector<unsigned char>& signed_message_buffer,
	std::uint64_t signed_message_length)
{
	std::uint32_t signed_message_length_32 =
		static_cast<std::uint32_t>(signed_message_length);

	std::vector<unsigned char> plaintext_buffer;

	// Append signer_public_key
	plaintext_buffer.insert(
		plaintext_buffer.end(),
		signer_public_key,
		signer_public_key + crypto_sign_PUBLICKEYBYTES);

	// Append 4 bytes of signed_message_size
	plaintext_buffer.insert(
		plaintext_buffer.end(),
		reinterpret_cast<const unsigned char*>(&signed_message_length_32),
		reinterpret_cast<const unsigned char*>(&signed_message_length_32) + sizeof(signed_message_length_32));

	// Append signed_message bytes (signature + payload)
	plaintext_buffer.insert(
		plaintext_buffer.end(),
		signed_message_buffer.begin(),
		signed_message_buffer.end());

	return plaintext_buffer;
}


// Encrypt plaintext using crypto_box (authenticated public-key encryption)
// Perform authenticated public-key encryption using crypto_box.
// The resulting ciphertext format is:
//   [MAC (crypto_box_MACBYTES)][encrypted plaintext bytes]
//
// The function also generates a fresh random nonce for each encryption.
static std::vector<unsigned char> encrypt_plaintext_to_ciphertext(
	const std::vector<unsigned char>& plaintext_buffer,
	const unsigned char kernel_recipient_public_key[crypto_box_PUBLICKEYBYTES],
	const unsigned char sender_encryption_secret_key[crypto_box_SECRETKEYBYTES],
	unsigned char nonce_out[crypto_box_NONCEBYTES],
	std::uint32_t& ciphertext_size_out)
{
	const std::size_t plaintext_size_in_bytes = plaintext_buffer.size();

	// NaCl/TweetNaCl requires crypto_box_ZEROBYTES leading zeros in the message.
	const std::size_t padded_plaintext_size_in_bytes =
		plaintext_size_in_bytes + crypto_box_ZEROBYTES;

	// Allocate padded plaintext buffer: [ZEROBYTES zeros][actual plaintext bytes].
	std::vector<unsigned char> padded_plaintext_buffer(padded_plaintext_size_in_bytes);
	std::memset(padded_plaintext_buffer.data(), 0, crypto_box_ZEROBYTES);
	std::memcpy(
		padded_plaintext_buffer.data() + crypto_box_ZEROBYTES,
		plaintext_buffer.data(),
		plaintext_size_in_bytes);

	// Ciphertext buffer has the same size as the padded plaintext buffer.
	std::vector<unsigned char> ciphertext_buffer(padded_plaintext_size_in_bytes);

	// Generate a fresh random nonce for this encryption operation.
	icr_randombytes(nonce_out, crypto_box_NONCEBYTES);

	// Perform authenticated public-key encryption.
	if (crypto_box(
		ciphertext_buffer.data(),
		padded_plaintext_buffer.data(),
		padded_plaintext_size_in_bytes,
		nonce_out,
		kernel_recipient_public_key,
		sender_encryption_secret_key) != 0)
	{
		throw std::runtime_error("crypto_box failed");
	}

	ciphertext_size_out = static_cast<std::uint32_t>(padded_plaintext_size_in_bytes);
	return ciphertext_buffer;
}

// Build the blacklist file header
// The header is placed at the beginning of the file. It tells the kernel:
//   - Which nonce was used for crypto_box
//   - Which sender encryption public key is associated with this ciphertext
//   - The size of the ciphertext in bytes
static BLACKLIST_FILE_HEADER build_blacklist_header(
	const unsigned char nonce[crypto_box_NONCEBYTES],
	const unsigned char sender_encryption_public_key[crypto_box_PUBLICKEYBYTES],
	std::uint32_t ciphertext_size)
{
	BLACKLIST_FILE_HEADER header{};
	std::memcpy(header.nonce, nonce, crypto_box_NONCEBYTES);
	std::memcpy(header.sender_encryption_public_key,
		sender_encryption_public_key,
		crypto_box_PUBLICKEYBYTES);
	header.ciphertext_size = ciphertext_size;
	return header;
}

// Write header and ciphertext to disk
// The kernel expects the file to contain:
//   [BLACKLIST_FILE_HEADER][ciphertext_bytes]
static bool write_header_and_ciphertext_to_file(
	const std::wstring& file_path,
	const BLACKLIST_FILE_HEADER& header,
	const std::vector<unsigned char>& ciphertext_buffer)
{
	FILE* file_handle = nullptr;
	errno_t open_status = _wfopen_s(&file_handle, file_path.c_str(), L"wb");
	if (open_status != 0 || file_handle == nullptr)
	{
		std::wcerr << L"Failed to open file for write: "
			<< file_path
			<< L" (errno=" << open_status << L")\n";
		return false;
	}

	size_t written_byte_count = std::fwrite(&header, 1, sizeof(header), file_handle);
	if (written_byte_count != sizeof(header))
	{
		std::cerr << "Failed to write header\n";
		std::fclose(file_handle);
		return false;
	}

	if (!ciphertext_buffer.empty())
	{
		written_byte_count = std::fwrite(ciphertext_buffer.data(),
			1,
			ciphertext_buffer.size(),
			file_handle);
		if (written_byte_count != ciphertext_buffer.size())
		{
			std::cerr << "Failed to write ciphertext\n";
			std::fclose(file_handle);
			return false;
		}
	}

	if (std::fflush(file_handle) != 0)
	{
		std::cerr << "Failed to flush file\n";
		std::fclose(file_handle);
		return false;
	}

	if (std::fclose(file_handle) != 0)
	{
		std::cerr << "Failed to close file\n";
		return false;
	}
	return true;
}

bool write_blacklist_file(
	const std::wstring& file_path,
	const std::vector<std::string>& path_list,
	const unsigned char kernel_recipient_public_key[crypto_box_PUBLICKEYBYTES],
	const unsigned char sender_encryption_public_key[crypto_box_PUBLICKEYBYTES],
	const unsigned char sender_encryption_secret_key[crypto_box_SECRETKEYBYTES],
	const unsigned char signer_public_key[crypto_sign_PUBLICKEYBYTES],
	const unsigned char signer_secret_key[crypto_sign_SECRETKEYBYTES])
{
	try
	{
		// 1. Serialize path list into payload format.
		std::vector<unsigned char> payload_buffer =
			build_payload_from_paths(path_list);

		// 2. Sign payload.
		std::uint64_t signed_message_length = 0;
		std::vector<unsigned char> signed_message_buffer =
			sign_payload(payload_buffer, signer_secret_key, signed_message_length);

		// 3. Build plaintext blob with signer public key and signed message size.
		std::vector<unsigned char> plaintext_buffer =
			build_plaintext_blob(signer_public_key,
				signed_message_buffer,
				signed_message_length);

		// 4. Encrypt plaintext blob with crypto_box and fresh nonce.
		unsigned char nonce[crypto_box_NONCEBYTES] = { 0 };
		std::uint32_t ciphertext_size = 0;
		std::vector<unsigned char> ciphertext_buffer =
			encrypt_plaintext_to_ciphertext(plaintext_buffer,
				kernel_recipient_public_key,
				sender_encryption_secret_key,
				nonce,
				ciphertext_size);

		// 5. Build header with nonce, sender public key and ciphertext size.
		BLACKLIST_FILE_HEADER header =
			build_blacklist_header(nonce, sender_encryption_public_key, ciphertext_size);

		// 6. Write header + ciphertext to disk.
		return write_header_and_ciphertext_to_file(
			file_path,
			header,
			ciphertext_buffer);
	}
	catch (const std::exception& exception_object)
	{
		std::cerr << "write_blacklist_file failed: "
			<< exception_object.what() << "\n";
		return false;
	}
}

// Generate a public/secret key pair for authenticated encryption (crypto_box)
bool generate_encryption_key_pair(
	unsigned char public_key[crypto_box_PUBLICKEYBYTES],
	unsigned char secret_key[crypto_box_SECRETKEYBYTES])
{
	if (crypto_box_keypair(public_key, secret_key) != 0)
	{
		return false;
	}
	return true;
}

// Generate a public/secret key pair for digital signatures (crypto_sign)
bool generate_signing_key_pair(
	unsigned char public_key[crypto_sign_PUBLICKEYBYTES],
	unsigned char secret_key[crypto_sign_SECRETKEYBYTES])
{
	if (crypto_sign_keypair(public_key, secret_key) != 0)
	{
		return false;
	}
	return true;
}

static bool save_key_to_file(
	const std::wstring& file_path,
	const unsigned char* key,
	std::size_t key_length)
{
	if (key == nullptr)
	{
		std::cerr << "save_key_pair_to_file: null key pointer\n";
		return false;
	}

	FILE* file_handle = nullptr;

	errno_t open_status = _wfopen_s(&file_handle, file_path.c_str(), L"wb");
	if (open_status != 0 || file_handle == nullptr)
	{
		std::wcerr << L"save_key_pair_to_file: failed to open file for write: "
			<< file_path << L" (errno=" << open_status << L")\n";
		return false;
	}

	std::size_t written_byte_count = std::fwrite(
		key,
		1,
		key_length,
		file_handle);

	if (written_byte_count != key_length)
	{
		std::cerr << "save_key_pair_to_file: failed to write public key\n";
		std::fclose(file_handle);
		return false;
	}

	if (std::fflush(file_handle) != 0)
	{
		std::cerr << "save_key_pair_to_file: failed to flush file\n";
		std::fclose(file_handle);
		return false;
	}

	if (std::fclose(file_handle) != 0)
	{
		std::cerr << "save_key_pair_to_file: failed to close file\n";
		return false;
	}
	return true;
}

static bool read_key_from_file(const std::wstring& file_path,
	unsigned char* key,
	std::size_t key_length) {
	if (key == nullptr)
	{
		std::cerr << "read_key_from_file: null key pointer\n";
		return false;
	}

	FILE* file_handle = nullptr;
	errno_t open_status = _wfopen_s(&file_handle, file_path.c_str(), L"rb");
	if (open_status != 0 || file_handle == nullptr)
	{
		std::wcerr << L"read_key_from_file: failed to open file for read: "
			<< file_path << L" (errno=" << open_status << L")\n";
		return false;
	}

	std::size_t read_byte_count = std::fread(
		key,
		1,
		key_length,
		file_handle);

	if (read_byte_count != key_length)
	{
		std::cerr << "read_key_from_file: failed to read public key\n";
		std::fclose(file_handle);
		return false;
	}

	if (std::fclose(file_handle) != 0)
	{
		std::cerr << "read_key_from_file: failed to close file\n";
		return false;
	}
	return true;
}

int main()
{
	unsigned char kernel_recipient_public_key[crypto_box_PUBLICKEYBYTES];
	unsigned char kernel_recipient_secret_key[crypto_box_SECRETKEYBYTES];
	unsigned char sender_encryption_public_key[crypto_box_PUBLICKEYBYTES];
	unsigned char sender_encryption_secret_key[crypto_box_SECRETKEYBYTES];
	unsigned char signer_public_key[crypto_sign_PUBLICKEYBYTES];
	unsigned char signer_secret_key[crypto_sign_SECRETKEYBYTES];

	/**
	// Generate kernel (recipient) key pair.
	// In a real system, this would be generated once and the secret key would be
	// stored securely in the kernel. The public key is distributed to user-mode.
	if (!generate_encryption_key_pair(kernel_recipient_public_key,
		kernel_recipient_secret_key))
	{
		std::cerr << "Failed to generate kernel encryption key pair\n";
		return 1;
	}

	save_key_to_file(L"E:\\workspace\\kernel_pub_key.txt", kernel_recipient_public_key, crypto_box_PUBLICKEYBYTES);
	save_key_to_file(L"E:\\workspace\\kernel_pri_key.txt", kernel_recipient_secret_key, crypto_box_SECRETKEYBYTES);

	// Generate sender encryption key pair (for crypto_box).
	if (!generate_encryption_key_pair(sender_encryption_public_key,
		sender_encryption_secret_key))
	{
		std::cerr << "Failed to generate sender encryption key pair\n";
		return 1;
	}

	save_key_to_file(L"E:\\workspace\\sender_encryption_pub_key.txt", sender_encryption_public_key, crypto_box_PUBLICKEYBYTES);
	save_key_to_file(L"E:\\workspace\\sender_encryption_pri_key.txt", sender_encryption_secret_key, crypto_box_SECRETKEYBYTES);

	// Generate signing key pair (for crypto_sign).
	if (!generate_signing_key_pair(signer_public_key, signer_secret_key))
	{
		std::cerr << "Failed to generate signing key pair\n";
		return 1;
	}

	save_key_to_file(L"E:\\workspace\\signer_pub_key.txt", signer_public_key, crypto_sign_PUBLICKEYBYTES);
	save_key_to_file(L"E:\\workspace\\signer_pri_key.txt", signer_secret_key, crypto_sign_SECRETKEYBYTES);

	// kernel_recipient_public_key   (to encrytion with crypto_box)
	// sender_encryption_public_key  (into header)
	// sender_encryption_secret_key  (to encrypt)
	// signer_public_key             (into plaintext blob)
	// signer_secret_key             (to sign)
	*/
	read_key_from_file(L"E:\\workspace\\kernel_pub_key.txt", kernel_recipient_public_key, crypto_box_PUBLICKEYBYTES);
	read_key_from_file(L"E:\\workspace\\sender_encryption_pub_key.txt", sender_encryption_public_key, crypto_box_PUBLICKEYBYTES);
	read_key_from_file(L"E:\\workspace\\sender_encryption_pri_key.txt", sender_encryption_secret_key, crypto_box_SECRETKEYBYTES);
	read_key_from_file(L"E:\\workspace\\signer_pub_key.txt", signer_public_key, crypto_sign_PUBLICKEYBYTES);
	read_key_from_file(L"E:\\workspace\\signer_pri_key.txt", signer_secret_key, crypto_sign_SECRETKEYBYTES);

	std::vector<std::string> path_list = {
		u8"\\device\\harddiskvolume2\\windows\\minifilter_secure_folder\\blacklist.txt",
		u8"\\device\\harddiskvolume5\\test\\y.txt",
		u8"\\device\\harddiskvolume5\\test\\yy.txt",
		u8"\\device\\harddiskvolume5\\test\\subfolder\\x.txt",
		u8"\\device\\harddiskvolume5\\test\\subfolder\\xx.txt",
		u8"\\device\\harddiskvolume5\\test\\subfolder\\y.txt",
		u8"\\device\\harddiskvolume5\\test\\subfolder\\yy.txt"
	};

	std::wstring file_path = L"C:\\FileSecDb\\blacklist.txt";

	if (!write_blacklist_file(file_path,
		path_list,
		kernel_recipient_public_key,
		sender_encryption_public_key,
		sender_encryption_secret_key,
		signer_public_key,
		signer_secret_key))
	{
		std::cerr << "write_blacklist_file failed\n";
		return 1;
	}

	std::cout << "Blacklist file written successfully.\n";
	return 0;
}
