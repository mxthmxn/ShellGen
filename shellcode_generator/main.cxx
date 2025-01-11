#include "ShellGen.hxx"
#include <iostream>
#include <windows.h>

int main()
{
	constexpr auto shellcode_size = 0x1000;
	const auto decrypt_shellcode = reinterpret_cast< unsigned char* >( VirtualAlloc( nullptr, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) );
	const auto encrypt_shellcode = reinterpret_cast< unsigned char* >( VirtualAlloc( nullptr, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) );

	if ( !decrypt_shellcode || !encrypt_shellcode )
		return -1;

	mxthmxn::ShellGen::generate( decrypt_shellcode, encrypt_shellcode, shellcode_size );

	const auto example_pointer = static_cast< void* >( AllocConsole );

	printf( "example pointer : %p\n", example_pointer );

	using encrypt_routine_t = void* ( * )( void*, void* );
	const auto encrypted = reinterpret_cast< encrypt_routine_t >( encrypt_shellcode )( example_pointer, reinterpret_cast< void* >( 0xdeadbeefdead ) );
	const auto decrypted = reinterpret_cast< encrypt_routine_t >( decrypt_shellcode )( encrypted, reinterpret_cast< void* >( 0xdeadbeefdead ) );

	printf( "encrypted : %p | decrypted : %p\n", encrypted, decrypted );

	return 0;
}