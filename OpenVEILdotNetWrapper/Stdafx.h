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


// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently

#pragma once

#include "VEIL.h"
#include "VEILCmsHeader.h"
#include "VEILFileSupport.h"

using namespace System;
using namespace DynamicJsonParser;
using namespace System::Reflection;
using namespace System::Runtime::InteropServices;
using namespace System::Web::Script::Serialization;

template<class T>
class internalWrapper
{
public:
	internalWrapper() {}
	~internalWrapper() {}

	std::shared_ptr<T> get() { return _value; }
	void set(std::shared_ptr<T> setTo) { _value = setTo; }
	bool operator!() { return !_value; }
	T* operator->() { if (!_value) return nullptr; return _value.get(); }
protected:
	std::shared_ptr<T> _value;
};


// Used in the file encrypt and decrypt routines
class StatusClass : public IFileVEILOperationStatus, public tsmod::IObject
{
public:
	StatusClass() {}
	virtual bool Status(const tsAscii& taskName, int taskNumber, int ofTaskCount, int taskPercentageDone)
	{
		//if (g_doStatus)
		//{
		//	ts_out << "Task " << taskNumber << " of " << ofTaskCount << " " << taskName << " " << taskPercentageDone << "%" << endl;
		//}
		return true;
	}
	virtual void    FailureReason(const tsAscii&failureText)
	{
		//ERROR(failureText);
	}

private:
	virtual ~StatusClass() {}
};

inline tsAscii StringToTsAscii(String^ str)
{
	tsAscii tmp;

	if (str != nullptr)
	{
		IntPtr glob = Marshal::StringToHGlobalAnsi(str);
		tmp = (const char*)glob.ToPointer();
		Marshal::FreeHGlobal(glob);
	}
	return tmp;
}
inline String^ tsAsciiToString(const tsAscii& value)
{
	return gcnew String(value.c_str());
}
inline System::Guid GUID2Guid(const GUID& value)
{
	return System::Guid(value.Data1, value.Data2, value.Data3, value.Data4[0], value.Data4[1], value.Data4[2], value.Data4[3], value.Data4[4], value.Data4[5], value.Data4[6], value.Data4[7]);
}
inline GUID Guid2GUID(System::Guid value)
{
	return ToGuid()(StringToTsAscii(value.ToString("B")));
}
inline array<byte>^ tsDataToByteArray(const tsData& value)
{
	array<byte>^ b = gcnew array<byte>(value.size());

	pin_ptr<byte> p = &b[0];
	memcpy(p, value.c_str(), value.size());
	return b;
}
inline tsData byteArrayToTsData(array<byte>^ value)
{
	tsData tmp;

	tmp.resize(value->Length);
	pin_ptr<byte> p = &value[0];
	memcpy(tmp.rawData(), p, tmp.size());
	return tmp;
}