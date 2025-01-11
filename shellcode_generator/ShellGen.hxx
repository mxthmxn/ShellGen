#pragma once
#include <cstdint>

/*
_________________________________________________________
Not removing this text is appreciated

Author: mxthmxn
Github: https://github.com/mxthmxn
ShellGen: Dynamic pointer encryption generator for Windows X64

___________________________________________________________
*/

namespace mxthmxn
{

	class ShellGen final
	{
	private:
		static void generate_call_recursive( unsigned char* decrypt_shellcode, unsigned char* encrypt_shellcode,
			unsigned long max_shellcode_size = 0x70, unsigned long min_shellcode_size = 0x30, int max_recursive_calls = 2 );

	public:
		static void generate( unsigned char* output_decrypt_shellcode, unsigned char* output_encrypt_shellcode, uint32_t shellcode_size,
			int max_count_of_recursive_calls = 2, unsigned long max_recursive_shellcode_size = 0x80, unsigned long min_recursive_shellcode_size = 0x30 );
	};

}

/*
________________________________________________________________________________
MIT License

Copyright (c) 2025 mxthmxn

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
________________________________________________________________________________
*/