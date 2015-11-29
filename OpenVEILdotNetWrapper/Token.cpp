//	Copyright (c) 2015, TecSec, Inc.
//
//	Redistribution and use in source and binary forms, with or without
//	modification, are permitted provided that the following conditions are met:
//	
//		* Redistributions of source code must retain the above copyright
//		  notice, this list of conditions and the following disclaimer.
//		* Redistributions in binary form must reproduce the above copyright
//		  notice, this list of conditions and the following disclaimer in the
//		  documentation and/or other materials provided with the distribution.
//		* Neither the name of TecSec nor the names of the contributors may be
//		  used to endorse or promote products derived from this software 
//		  without specific prior written permission.
//		 
//	ALTERNATIVELY, provided that this notice is retained in full, this product
//	may be distributed under the terms of the GNU General Public License (GPL),
//	in which case the provisions of the GPL apply INSTEAD OF those given above.
//		 
//	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//	DISCLAIMED.  IN NO EVENT SHALL TECSEC BE LIABLE FOR ANY 
//	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//	LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

// This is the main DLL file.

#include "stdafx.h"

#include "OpenVEILdotNetWrapper.h"

namespace OpenVEIL {
	Token::Token() : _dataHolder(nullptr)
	{}
	Token::Token(std::shared_ptr<IToken> _tok) : _dataHolder(new internalWrapper<IToken>())
	{
		_dataHolder->set(_tok);
	}
	Token::~Token()
	{
		release();
	}

	void Token::release()
	{
		if (_dataHolder == nullptr)
		{
			delete _dataHolder;
			_dataHolder = nullptr;
		}
	}

	String^ Token::tokenName::get()
	{
		if (!isReady())
			return nullptr;
		return tsAsciiToString(handle()->tokenName());
	}
	void Token::tokenName::set(String^ setTo)
	{
		if (!isReady())
			return;
		handle()->tokenName(StringToTsAscii(setTo));
	}
	array<byte>^ Token::serialNumber()
	{
		if (!isReady())
			return nullptr;
		return tsDataToByteArray(handle()->serialNumber());
	}
	System::Guid Token::id::get()
	{
		if (!isReady())
			return System::Guid::Empty;
		return GUID2Guid(handle()->id());
	}
	String^ Token::enterpriseName::get()
	{
		if (!isReady())
			return nullptr;
		return tsAsciiToString(handle()->enterpriseName());
	}
	String^ Token::memberName::get()
	{
		if (!isReady())
			return nullptr;
		return tsAsciiToString(handle()->memberName());
	}
	String^ Token::tokenType::get()
	{
		if (!isReady())
			return nullptr;
		return tsAsciiToString(handle()->tokenType());
	}
	System::Guid Token::enterpriseId::get()
	{
		if (!isReady())
			return System::Guid::Empty;
		return GUID2Guid(handle()->enterpriseId());
	}
	System::Guid Token::memberId::get()
	{
		if (!isReady())
			return System::Guid::Empty;
		return GUID2Guid(handle()->memberId());
	}
	Session^ Token::openSession()
	{
		if (!isReady())
			return nullptr;
		return gcnew Session(handle()->openSession());
	}

	std::shared_ptr<IToken> Token::handle() { if (_dataHolder == nullptr) return nullptr; return _dataHolder->get(); }

	bool Token::isReady()
	{
		return _dataHolder != nullptr && !!_dataHolder->get();
	}
}