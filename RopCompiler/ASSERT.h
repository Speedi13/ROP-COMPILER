#pragma once

#define __WIDE__TEXT(quote) L ## quote
#define __assert__(_Expression) (void)( (!!(_Expression)) || (AssertW(__WIDE__TEXT(#_Expression), __FILEW__, __LINE__), 0) )
#define __ASSERT__( _Expression ) __assert__( _Expression )

void __cdecl AssertW( const wchar_t * _Message, const wchar_t *_File, unsigned _Line);
