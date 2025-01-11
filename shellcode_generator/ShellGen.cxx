#include "ShellGen.hxx"
#include <windows.h>
#include <random>

enum InstructionType : int
{
	ANTIDISASSEMBLY,
	ADD_KEY,
	SUB_KEY,
	XOR_KEY,
	ROR,
	ROL,
	ADD,
	SUB,
	XOR,
	NOT,
	CALL
};

std::random_device rd;
std::mt19937_64 gen( rd( ) );

constexpr uint16_t count_of_instruction_types = 11;
constexpr uint32_t bigger_instruction_length = 13;
constexpr uint32_t ret_instruction_length = 1;

void mxthmxn::ShellGen::generate_call_recursive( unsigned char* decrypt_shellcode, unsigned char* encrypt_shellcode,
	unsigned long max_shellcode_size, unsigned long min_shellcode_size, int max_recursive_calls )
{
	unsigned char end_shellcode [ ] = {
		0xc3		// ret
	};

	std::uniform_int_distribution<uint32_t> shellcode_size( min_shellcode_size, max_shellcode_size );
	std::uniform_int_distribution<uint64_t> dist64( 1, UINT64_MAX );
	std::uniform_int_distribution<uint16_t> dist8( 1, UINT8_MAX );
	uint32_t bytes_filled = 0x0;
	auto bytes_to_fill = shellcode_size( gen );
	const auto shellcode_bytes = bytes_to_fill;
	const auto can_use_call = max_recursive_calls > 0;
	const auto instructions_type_range = can_use_call ? count_of_instruction_types : count_of_instruction_types - 1;

	memset( encrypt_shellcode, 0x90, shellcode_bytes );
	memset( decrypt_shellcode, 0x90, shellcode_bytes );

	while ( bytes_to_fill >= bigger_instruction_length + ret_instruction_length )
	{
		const auto shellcode_type = std::rand( ) % instructions_type_range;

		switch ( shellcode_type )
		{
		case ANTIDISASSEMBLY:
		{

		}
		case ADD_KEY:
		{
			unsigned char add_key_shellcode [ ] = {
				0x48, 0x01, 0xd0	// add rax, rdx
			};
			unsigned char sub_key_shellcode [ ] = {
				0x48, 0x29, 0xd0,	// sub rax, rdx
			};
			const auto instruction_size = sizeof( add_key_shellcode );
			const auto encrypt_bytes = encrypt_shellcode + bytes_filled;
			const auto decrypt_bytes = decrypt_shellcode + shellcode_bytes - sizeof( end_shellcode ) - bytes_filled - instruction_size;

			memcpy( encrypt_bytes, add_key_shellcode, instruction_size );
			memcpy( decrypt_bytes, sub_key_shellcode, instruction_size );

			bytes_filled += instruction_size;
			bytes_to_fill -= instruction_size;
			break;
		}
		case SUB_KEY:
		{
			unsigned char sub_key_shellcode [ ] = {
				0x48, 0x29, 0xd0,	// sub rax, rdx
			};
			unsigned char add_key_shellcode [ ] = {
				0x48, 0x01, 0xd0	// add rax, rdx
			};
			const auto instruction_size = sizeof( sub_key_shellcode );
			const auto encrypt_bytes = encrypt_shellcode + bytes_filled;
			const auto decrypt_bytes = decrypt_shellcode + shellcode_bytes - sizeof( end_shellcode ) - bytes_filled - instruction_size;

			memcpy( encrypt_bytes, sub_key_shellcode, instruction_size );
			memcpy( decrypt_bytes, add_key_shellcode, instruction_size );

			bytes_filled += instruction_size;
			bytes_to_fill -= instruction_size;
			break;
		}
		case XOR_KEY:
		{
			unsigned char xor_key_shellcode [ ] = {
				0x48, 0x31, 0xd0
			};
			const auto instruction_size = sizeof( xor_key_shellcode );
			const auto encrypt_bytes = encrypt_shellcode + bytes_filled;
			const auto decrypt_bytes = decrypt_shellcode + shellcode_bytes - sizeof( end_shellcode ) - bytes_filled - instruction_size;

			memcpy( encrypt_bytes, xor_key_shellcode, instruction_size );
			memcpy( decrypt_bytes, xor_key_shellcode, instruction_size );

			bytes_filled += instruction_size;
			bytes_to_fill -= instruction_size;
			break;
		}
		case ROR:
		{
			unsigned char ror_rax_shellcode [ ] = {
				0x48, 0xc1, 0xc8, 0x00,	// ror rax, 0
			};
			unsigned char rol_rax_shellcode [ ] = {
				0x48, 0xc1, 0xc0, 0x00, // rol rax, 0
			};
			const auto instruction_size = sizeof( ror_rax_shellcode );
			const auto encrypt_bytes = encrypt_shellcode + bytes_filled;
			const auto decrypt_bytes = decrypt_shellcode + shellcode_bytes - sizeof( end_shellcode ) - bytes_filled - instruction_size;
			const auto shift_value = static_cast< uint8_t >( dist8( gen ) );

			*( unsigned char* ) ( ror_rax_shellcode + 3 ) = shift_value;
			*( unsigned char* ) ( rol_rax_shellcode + 3 ) = shift_value;

			memcpy( encrypt_bytes, ror_rax_shellcode, instruction_size );
			memcpy( decrypt_bytes, rol_rax_shellcode, instruction_size );

			bytes_filled += instruction_size;
			bytes_to_fill -= instruction_size;
			break;
		}
		case ROL:
		{
			unsigned char rol_rax_shellcode [ ] = {
				0x48, 0xc1, 0xc0, 0x00, // rol rax, 0
			};
			unsigned char ror_rax_shellcode [ ] = {
				0x48, 0xc1, 0xc8, 0x00,	// ror rax, 0
			};
			const auto instruction_size = sizeof( rol_rax_shellcode );
			const auto encrypt_bytes = encrypt_shellcode + bytes_filled;
			const auto decrypt_bytes = decrypt_shellcode + shellcode_bytes - sizeof( end_shellcode ) - bytes_filled - instruction_size;
			const auto shift_value = static_cast< uint8_t >( dist8( gen ) );

			*( unsigned char* ) ( ror_rax_shellcode + 3 ) = shift_value;
			*( unsigned char* ) ( rol_rax_shellcode + 3 ) = shift_value;

			memcpy( encrypt_bytes, rol_rax_shellcode, instruction_size );
			memcpy( decrypt_bytes, ror_rax_shellcode, instruction_size );

			bytes_filled += instruction_size;
			bytes_to_fill -= instruction_size;
			break;
		}
		case ADD:
		{
			unsigned char add_rax_shellcode [ ] = {
				0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rcx, 0
				0x48, 0x01, 0xc8	// add rax, rcx
			};
			unsigned char sub_rax_shellcode [ ] = {
				0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rcx, 0
				0x48, 0x29, 0xc8	// sub rax, rcx
			};
			const auto instruction_size = sizeof( add_rax_shellcode );
			const auto encrypt_bytes = encrypt_shellcode + bytes_filled;
			const auto decrypt_bytes = decrypt_shellcode + shellcode_bytes - sizeof( end_shellcode ) - bytes_filled - instruction_size;
			const auto mov_value = dist64( gen );

			*( uintptr_t* ) ( add_rax_shellcode + 2 ) = mov_value;
			*( uintptr_t* ) ( sub_rax_shellcode + 2 ) = mov_value;

			memcpy( encrypt_bytes, add_rax_shellcode, instruction_size );
			memcpy( decrypt_bytes, sub_rax_shellcode, instruction_size );

			bytes_filled += instruction_size;
			bytes_to_fill -= instruction_size;
			break;
		}
		case SUB:
		{
			unsigned char sub_rax_shellcode [ ] = {
				0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rcx, 0
				0x48, 0x29, 0xc8	// sub rax, rcx
			};
			unsigned char add_rax_shellcode [ ] = {
				0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rcx, 0
				0x48, 0x01, 0xc8	// add rax, rcx
			};
			const auto instruction_size = sizeof( sub_rax_shellcode );
			const auto encrypt_bytes = encrypt_shellcode + bytes_filled;
			const auto decrypt_bytes = decrypt_shellcode + shellcode_bytes - sizeof( end_shellcode ) - bytes_filled - instruction_size;
			const auto mov_value = dist64( gen );

			*( uintptr_t* ) ( sub_rax_shellcode + 2 ) = mov_value;
			*( uintptr_t* ) ( add_rax_shellcode + 2 ) = mov_value;

			memcpy( encrypt_bytes, sub_rax_shellcode, instruction_size );
			memcpy( decrypt_bytes, add_rax_shellcode, instruction_size );

			bytes_filled += instruction_size;
			bytes_to_fill -= instruction_size;
			break;
		}
		case XOR:
		{
			unsigned char xor_rax_shellcode [ ] = {
				0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rcx, 0
				0x48, 0x31, 0xc8	// xor rax, rcx
			};
			const auto instruction_size = sizeof( xor_rax_shellcode );
			const auto encrypt_bytes = encrypt_shellcode + bytes_filled;
			const auto decrypt_bytes = decrypt_shellcode + shellcode_bytes - sizeof( end_shellcode ) - bytes_filled - instruction_size;
			const auto mov_value = dist64( gen );

			*( uintptr_t* ) ( xor_rax_shellcode + 2 ) = mov_value;

			memcpy( encrypt_bytes, xor_rax_shellcode, instruction_size );
			memcpy( decrypt_bytes, xor_rax_shellcode, instruction_size );

			bytes_filled += instruction_size;
			bytes_to_fill -= instruction_size;
			break;
		}
		case NOT:
		{
			unsigned char not_shellcode [ ] = {
				0x48, 0xf7, 0xd0 // not rax
			};

			const auto instruction_size = sizeof( not_shellcode );
			const auto encrypt_bytes = encrypt_shellcode + bytes_filled;
			const auto decrypt_bytes = decrypt_shellcode + shellcode_bytes - sizeof( end_shellcode ) - bytes_filled - instruction_size;

			memcpy( encrypt_bytes, not_shellcode, instruction_size );
			memcpy( decrypt_bytes, not_shellcode, instruction_size );

			bytes_filled += instruction_size;
			bytes_to_fill -= instruction_size;
			break;
		}
		case CALL:
		{
			unsigned char call_shellcode [ ] = {
				0xe8, 0x00, 0x00, 0x00, 0x00 // near call
			};
			const auto instruction_size = sizeof( call_shellcode );
			const auto encrypt_bytes = encrypt_shellcode + bytes_filled;
			const auto decrypt_bytes = decrypt_shellcode + shellcode_bytes - sizeof( end_shellcode ) - bytes_filled - instruction_size;
			const auto decrypt_address = reinterpret_cast< uintptr_t >( VirtualAlloc( nullptr, max_shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) );
			const auto encrypt_address = reinterpret_cast< uintptr_t >( VirtualAlloc( nullptr, max_shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) );
			const auto decrypt_offset = decrypt_address - reinterpret_cast< uintptr_t >( decrypt_bytes ) - sizeof( int ) - 1;
			const auto encrypt_offset = encrypt_address - reinterpret_cast< uintptr_t >( encrypt_bytes ) - sizeof( int ) - 1;

			*( uint32_t* ) ( call_shellcode + 1 ) = encrypt_offset;

			memcpy( encrypt_bytes, call_shellcode, instruction_size );

			*( uint32_t* ) ( call_shellcode + 1 ) = decrypt_offset;

			memcpy( decrypt_bytes, call_shellcode, instruction_size );

			generate_call_recursive( reinterpret_cast< unsigned char* >( decrypt_address ), reinterpret_cast< unsigned char* >( encrypt_address ),
				max_shellcode_size, min_shellcode_size, max_recursive_calls - 1 );

			bytes_filled += instruction_size;
			bytes_to_fill -= instruction_size;
			break;
		}
		}

		memcpy( decrypt_shellcode + shellcode_bytes - sizeof( end_shellcode ), end_shellcode, sizeof( end_shellcode ) );
		memcpy( encrypt_shellcode + shellcode_bytes - sizeof( end_shellcode ), end_shellcode, sizeof( end_shellcode ) );
	}
}

void mxthmxn::ShellGen::generate( unsigned char* output_decrypt_shellcode, unsigned char* output_encrypt_shellcode,
	uint32_t shellcode_size, int max_count_of_recursive_calls, unsigned long max_recursive_shellcode_size, unsigned long min_recursive_shellcode_size )
{
	static bool is_time_initialized = false;
	
	if ( !is_time_initialized )
	{
		std::srand( std::time( nullptr ) );
		is_time_initialized = true;
	}

	std::uniform_int_distribution<uint64_t> dist64( 1, UINT64_MAX );
	std::uniform_int_distribution<uint16_t> dist8( 1, UINT8_MAX );

	unsigned char initial_shellcode [ ] = {
		0x48, 0x8b, 0xc1,	// mov rax, rcx
		0x74, 0x03, 0x75, 0x01, 0xe8 // jz 3 jne 1 e8
	};
	unsigned char end_shellcode [ ] = {
		0xc3				// ret
	};

	memcpy( output_decrypt_shellcode, initial_shellcode, sizeof( initial_shellcode ) );
	memcpy( output_decrypt_shellcode + shellcode_size - sizeof( end_shellcode ), end_shellcode, sizeof( end_shellcode ) );
	memcpy( output_encrypt_shellcode, initial_shellcode, sizeof( initial_shellcode ) );
	memcpy( output_encrypt_shellcode + shellcode_size - sizeof( end_shellcode ), end_shellcode, sizeof( end_shellcode ) );

	size_t bytes_to_fill = shellcode_size - sizeof( initial_shellcode ) - sizeof( end_shellcode );
	size_t bytes_filled = 0x0;
	while ( bytes_to_fill >= bigger_instruction_length )
	{
		int shellcode_type = std::rand( ) % count_of_instruction_types;

		switch ( shellcode_type )
		{
			case ANTIDISASSEMBLY:
			{
				unsigned char antidisassembly_shellcode [ ] = {
						0x74, 0x03, 0x75, 0x01, 0xe8 // jz 3 jne 1 e8
				};

				const auto instruction_size = sizeof( antidisassembly_shellcode );
				const auto encrypt_bytes = output_encrypt_shellcode + sizeof( initial_shellcode ) + bytes_filled;
				const auto decrypt_bytes = output_decrypt_shellcode + shellcode_size - sizeof( end_shellcode ) - bytes_filled - instruction_size;

				memcpy( encrypt_bytes, antidisassembly_shellcode, instruction_size );
				memcpy( decrypt_bytes, antidisassembly_shellcode, instruction_size );

				bytes_filled += instruction_size;
				bytes_to_fill -= instruction_size;
				break;
			}
			case ROR:
			{
				unsigned char ror_rax_shellcode [ ] = {
					0x48, 0xc1, 0xc8, 0x00,	// ror rax, 0
				};
				unsigned char rol_rax_shellcode [ ] = {
					0x48, 0xc1, 0xc0, 0x00, // rol rax, 0
				};
				const auto instruction_size = sizeof( ror_rax_shellcode );
				const auto encrypt_bytes = output_encrypt_shellcode + sizeof( initial_shellcode ) + bytes_filled;
				const auto decrypt_bytes = output_decrypt_shellcode + shellcode_size - sizeof( end_shellcode ) - bytes_filled - instruction_size;
				const auto shift_value = static_cast< uint8_t >( dist8( gen ) );

				*( unsigned char* ) ( ror_rax_shellcode + 3 ) = shift_value;
				*( unsigned char* ) ( rol_rax_shellcode + 3 ) = shift_value;

				memcpy( encrypt_bytes, ror_rax_shellcode, instruction_size );
				memcpy( decrypt_bytes, rol_rax_shellcode, instruction_size );

				bytes_filled += instruction_size;
				bytes_to_fill -= instruction_size;
				break;
			}
			case ROL:
			{
				unsigned char rol_rax_shellcode [ ] = {
					0x48, 0xc1, 0xc0, 0x00, // rol rax, 0
				};
				unsigned char ror_rax_shellcode [ ] = {
					0x48, 0xc1, 0xc8, 0x00,	// ror rax, 0
				};
				const auto instruction_size = sizeof( rol_rax_shellcode );
				const auto encrypt_bytes = output_encrypt_shellcode + sizeof( initial_shellcode ) + bytes_filled;
				const auto decrypt_bytes = output_decrypt_shellcode + shellcode_size - sizeof( end_shellcode ) - bytes_filled - instruction_size;
				const auto shift_value = static_cast< uint8_t >( dist8( gen ) );

				*( unsigned char* ) ( ror_rax_shellcode + 3 ) = shift_value;
				*( unsigned char* ) ( rol_rax_shellcode + 3 ) = shift_value;

				memcpy( encrypt_bytes, rol_rax_shellcode, instruction_size );
				memcpy( decrypt_bytes, ror_rax_shellcode, instruction_size );

				bytes_filled += instruction_size;
				bytes_to_fill -= instruction_size;
				break;
			}
			case ADD:
			{
				unsigned char add_rax_shellcode [ ] = {
					0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rcx, 0
					0x48, 0x01, 0xc8	// add rax, rcx
				};
				unsigned char sub_rax_shellcode [ ] = {
					0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rcx, 0
					0x48, 0x29, 0xc8	// sub rax, rcx
				};
				const auto instruction_size = sizeof( add_rax_shellcode );
				const auto encrypt_bytes = output_encrypt_shellcode + sizeof( initial_shellcode ) + bytes_filled;
				const auto decrypt_bytes = output_decrypt_shellcode + shellcode_size - sizeof( end_shellcode ) - bytes_filled - instruction_size;
				const auto mov_value = dist64( gen );

				*( uintptr_t* ) ( add_rax_shellcode + 2 ) = mov_value;
				*( uintptr_t* ) ( sub_rax_shellcode + 2 ) = mov_value;

				memcpy( encrypt_bytes, add_rax_shellcode, instruction_size );
				memcpy( decrypt_bytes, sub_rax_shellcode, instruction_size );

				bytes_filled += instruction_size;
				bytes_to_fill -= instruction_size;
				break;
			}
			case SUB:
			{
				unsigned char sub_rax_shellcode [ ] = {
					0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rcx, 0
					0x48, 0x29, 0xc8	// sub rax, rcx
				};
				unsigned char add_rax_shellcode [ ] = {
					0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rcx, 0
					0x48, 0x01, 0xc8	// add rax, rcx
				};
				const auto instruction_size = sizeof( sub_rax_shellcode );
				const auto encrypt_bytes = output_encrypt_shellcode + sizeof( initial_shellcode ) + bytes_filled;
				const auto decrypt_bytes = output_decrypt_shellcode + shellcode_size - sizeof( end_shellcode ) - bytes_filled - instruction_size;
				const auto mov_value = dist64( gen );

				*( uintptr_t* ) ( sub_rax_shellcode + 2 ) = mov_value;
				*( uintptr_t* ) ( add_rax_shellcode + 2 ) = mov_value;

				memcpy( encrypt_bytes, sub_rax_shellcode, instruction_size );
				memcpy( decrypt_bytes, add_rax_shellcode, instruction_size );

				bytes_filled += instruction_size;
				bytes_to_fill -= instruction_size;
				break;
			}
			case XOR:
			{
				unsigned char xor_rax_shellcode [ ] = {
					0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rcx, 0
					0x48, 0x31, 0xc8	// xor rax, rcx
				};
				const auto instruction_size = sizeof( xor_rax_shellcode );
				const auto encrypt_bytes = output_encrypt_shellcode + sizeof( initial_shellcode ) + bytes_filled;
				const auto decrypt_bytes = output_decrypt_shellcode + shellcode_size - sizeof( end_shellcode ) - bytes_filled - instruction_size;
				const auto mov_value = dist64( gen );

				*( uintptr_t* ) ( xor_rax_shellcode + 2 ) = mov_value;

				memcpy( encrypt_bytes, xor_rax_shellcode, instruction_size );
				memcpy( decrypt_bytes, xor_rax_shellcode, instruction_size );

				bytes_filled += instruction_size;
				bytes_to_fill -= instruction_size;
				break;
			}
			case NOT:
			{
				unsigned char not_shellcode [ ] = {
					0x48, 0xf7, 0xd0 // not rax
				};
				const auto instruction_size = sizeof( not_shellcode );
				const auto encrypt_bytes = output_encrypt_shellcode + sizeof( initial_shellcode ) + bytes_filled;
				const auto decrypt_bytes = output_decrypt_shellcode + shellcode_size - sizeof( end_shellcode ) - bytes_filled - instruction_size;

				memcpy( encrypt_bytes, not_shellcode, instruction_size );
				memcpy( decrypt_bytes, not_shellcode, instruction_size );

				bytes_filled += instruction_size;
				bytes_to_fill -= instruction_size;
				break;
			}
			case ADD_KEY:
			{
				unsigned char add_key_shellcode [ ] = {
					0x48, 0x01, 0xd0	// add rax, rdx
				};
				unsigned char sub_key_shellcode [ ] = {
					0x48, 0x29, 0xd0,	// sub rax, rdx
				};
				const auto instruction_size = sizeof( add_key_shellcode );
				const auto encrypt_bytes = output_encrypt_shellcode + sizeof( initial_shellcode ) + bytes_filled;
				const auto decrypt_bytes = output_decrypt_shellcode + shellcode_size - sizeof( end_shellcode ) - bytes_filled - instruction_size;

				memcpy( encrypt_bytes, add_key_shellcode, instruction_size );
				memcpy( decrypt_bytes, sub_key_shellcode, instruction_size );

				bytes_filled += instruction_size;
				bytes_to_fill -= instruction_size;
				break;
			}
			case SUB_KEY:
			{
				unsigned char sub_key_shellcode [ ] = {
					0x48, 0x29, 0xd0,	// sub rax, rdx
				};
				unsigned char add_key_shellcode [ ] = {
					0x48, 0x01, 0xd0	// add rax, rdx
				};
				const auto instruction_size = sizeof( sub_key_shellcode );
				const auto encrypt_bytes = output_encrypt_shellcode + sizeof( initial_shellcode ) + bytes_filled;
				const auto decrypt_bytes = output_decrypt_shellcode + shellcode_size - sizeof( end_shellcode ) - bytes_filled - instruction_size;

				memcpy( encrypt_bytes, sub_key_shellcode, instruction_size );
				memcpy( decrypt_bytes, add_key_shellcode, instruction_size );

				bytes_filled += instruction_size;
				bytes_to_fill -= instruction_size;
				break;
			}
			case XOR_KEY:
			{
				unsigned char xor_key_shellcode [ ] = {
					0x48, 0x31, 0xd0	// xor rax, rdx
				};
				const auto instruction_size = sizeof( xor_key_shellcode );
				const auto encrypt_bytes = output_encrypt_shellcode + sizeof( initial_shellcode ) + bytes_filled;
				const auto decrypt_bytes = output_decrypt_shellcode + shellcode_size - sizeof( end_shellcode ) - bytes_filled - instruction_size;

				memcpy( encrypt_bytes, xor_key_shellcode, instruction_size );
				memcpy( decrypt_bytes, xor_key_shellcode, instruction_size );

				bytes_filled += instruction_size;
				bytes_to_fill -= instruction_size;
				break;
			}
			case CALL:
			{
				unsigned char call_shellcode [ ] = {
					0xe8, 0x00, 0x00, 0x00, 0x00 // near call
				};
				const auto instruction_size = sizeof( call_shellcode );
				const auto encrypt_bytes = output_encrypt_shellcode + sizeof( initial_shellcode ) + bytes_filled;
				const auto decrypt_bytes = output_decrypt_shellcode + shellcode_size - sizeof( end_shellcode ) - bytes_filled - instruction_size;
				const auto decrypt_address = ( uintptr_t ) VirtualAlloc( nullptr, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
				const auto encrypt_address = ( uintptr_t ) VirtualAlloc( nullptr, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
				const auto decrypt_offset = decrypt_address - reinterpret_cast< uintptr_t >( decrypt_bytes ) - sizeof( int ) - 1;
				const auto encrypt_offset = encrypt_address - reinterpret_cast< uintptr_t >( encrypt_bytes ) - sizeof( int ) - 1;

				*( uint32_t* ) ( call_shellcode + 1 ) = encrypt_offset;

				memcpy( encrypt_bytes, call_shellcode, instruction_size );

				*( uint32_t* ) ( call_shellcode + 1 ) = decrypt_offset;

				memcpy( decrypt_bytes, call_shellcode, instruction_size );

				generate_call_recursive( reinterpret_cast< unsigned char* >( decrypt_address ), reinterpret_cast< unsigned char* >( encrypt_address ),
					max_recursive_shellcode_size, min_recursive_shellcode_size, max_count_of_recursive_calls );

				bytes_filled += instruction_size;
				bytes_to_fill -= instruction_size;
				break;
			}
		}
	}

	const auto encrypt_bytes = output_encrypt_shellcode + sizeof( initial_shellcode ) + bytes_filled;
	const auto decrypt_bytes = output_decrypt_shellcode + shellcode_size - sizeof( end_shellcode ) - bytes_filled - bytes_to_fill;
	for ( auto idx = 0; idx < bytes_to_fill; idx++ )
	{
		encrypt_bytes [ idx ] = 0x90;
		decrypt_bytes [ idx ] = 0x90;
	}
}