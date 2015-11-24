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


// OpenVEILdotNetWrapper.h

#pragma once

#include "OpenVEIL.h"

using namespace System;
using namespace DynamicJsonParser;
using namespace System::Reflection;
using namespace System::Runtime::InteropServices;
using namespace System::Web::Script::Serialization;

namespace OpenVEIL {

	class ConnectionWrapper
	{
	public:
		ConnectionWrapper() {}
		~ConnectionWrapper() {}

		void set(std::shared_ptr<IKeyVEILConnector> setTo) { _value = setTo; }
		bool operator!() { return !_value; }
		IKeyVEILConnector* operator->() { if (!_value) return nullptr; return _value.get(); }
	protected:
		std::shared_ptr<IKeyVEILConnector> _value;
	};

	public ref class Connector abstract
	{
	public:
		Connector() :
			_conn(new ConnectionWrapper())
		{
			_conn->set(::ServiceLocator()->try_get_instance<IKeyVEILConnector>("/KeyVEILConnector"));
		}
		virtual ~Connector()
		{
			if (_conn != nullptr)
				delete _conn;
			_conn = nullptr;
		}
		virtual int connect(String^ url, String^ username, String^ password) = 0;
		virtual void disconnect()
		{
			if (isConnected())
			{
				(*_conn)->disconnect();
			}
		}
		virtual bool isConnected()
		{
			if (isReady())
			{
				return (*_conn)->isConnected();
			}
			else
			{
				return false;
			}
		}
		virtual bool sendJsonRequest(String^ verb, String^ cmd, DynamicJsonObject^ inData, [Out]DynamicJsonObject^% outData, [Out]int% status)
		{
			return sendJsonRequest(verb, cmd, inData->ToString(), outData, status);
		}
		virtual bool sendJsonRequest(String^ verb, String^ cmd, String^ inData, [Out]DynamicJsonObject^% outData, [Out]int% status)
		{
			status = 0;
			outData = nullptr;
			if (!isReady())
			{
				return false;
			}

			tsAscii Verb, Cmd, InData;

			IntPtr glob = Marshal::StringToHGlobalAnsi(verb);
			Verb = (const char*)glob.ToPointer();
			Marshal::FreeHGlobal(glob);

			glob = Marshal::StringToHGlobalAnsi(cmd);
			Cmd = (const char*)glob.ToPointer();
			Marshal::FreeHGlobal(glob);

			glob = Marshal::StringToHGlobalAnsi(inData);
			InData = (const char*)glob.ToPointer();
			Marshal::FreeHGlobal(glob);

			JSONObject inDataTmp;
			JSONObject outDataTmp;
			int stat;

			if (inDataTmp.FromJSON(InData.c_str()) <= 0)
			{
				return false;
			}

			if (!(*_conn)->sendJsonRequest(Verb, Cmd, inDataTmp, outDataTmp, stat))
			{
				status = stat;
				JavaScriptSerializer^ serializer = gcnew JavaScriptSerializer();
				serializer->RegisterConverters(gcnew array<JavaScriptConverter^> { gcnew DynamicJsonConverter() });

				outData = serializer->Deserialize<DynamicJsonObject^>(gcnew String(outDataTmp.ToJSON().c_str()));
				return false;
			}

			status = stat;
			JavaScriptSerializer^ serializer = gcnew JavaScriptSerializer();
			serializer->RegisterConverters(gcnew array<JavaScriptConverter^> { gcnew DynamicJsonConverter() });

			outData = serializer->Deserialize<DynamicJsonObject^>(gcnew String(outDataTmp.ToJSON().c_str()));
			return true;
		}
		virtual bool sendRequest(String^ verb, String^ cmd, array<byte>^ inData, [Out]array<byte>^% outData, [Out]int% status)
		{
			status = 0;
			outData = nullptr;
			if (!isReady())
			{
				return false;
			}

			tsAscii Verb, Cmd;

			IntPtr glob = Marshal::StringToHGlobalAnsi(verb);
			Verb = (const char*)glob.ToPointer();
			Marshal::FreeHGlobal(glob);

			glob = Marshal::StringToHGlobalAnsi(cmd);
			Cmd = (const char*)glob.ToPointer();
			Marshal::FreeHGlobal(glob);

			pin_ptr<byte> p;
			p = &inData[0];

			tsData tmp(p, inData->Length);
			tsData outDataTmp;

			int stat;

			if (!(*_conn)->sendRequest(Verb, Cmd, tmp, outDataTmp, stat))
			{
				status = stat;
				outData = gcnew array<byte>(outDataTmp.size());
				p = &outData[0];
				memcpy(p, outDataTmp.c_str(), outDataTmp.size());
				return false;
			}

			status = stat;
			outData = gcnew array<byte>(outDataTmp.size());
			p = &outData[0];
			memcpy(p, outDataTmp.c_str(), outDataTmp.size());
			return true;
		}
		virtual bool sendRequestBase64(String^ verb, String^ cmd, String^ inData, [Out]String^% outData, [Out]int% status)
		{
			status = 0;
			outData = nullptr;
			if (!isReady())
			{
				return false;
			}

			tsAscii Verb, Cmd, InData;

			IntPtr glob = Marshal::StringToHGlobalAnsi(verb);
			Verb = (const char*)glob.ToPointer();
			Marshal::FreeHGlobal(glob);

			glob = Marshal::StringToHGlobalAnsi(cmd);
			Cmd = (const char*)glob.ToPointer();
			Marshal::FreeHGlobal(glob);

			glob = Marshal::StringToHGlobalAnsi(inData);
			InData = (const char*)glob.ToPointer();
			Marshal::FreeHGlobal(glob);

			tsData outDataTmp;

			int stat;

			if (!(*_conn)->sendRequest(Verb, Cmd, InData.Base64ToData(), outDataTmp, stat))
			{
				status = stat;
				outData = gcnew String(outDataTmp.ToBase64().c_str());
				return false;
			}

			status = stat;
			outData = gcnew String(outDataTmp.ToBase64().c_str());
			return true;
		}

	protected:
		ConnectionWrapper* _conn;
		bool isReady()
		{
			return _conn != nullptr || !!(*_conn);
		}
	};
	public ref class GenericConnector : public Connector
	{
	public:
		virtual int connect(String^ url, String^ username, String^ password) override
		{
			if (!isReady())
			{
				return connStatus_NoServer;
			}
			tsAscii Url, Username, Password;

			IntPtr glob = Marshal::StringToHGlobalAnsi(url);
			Url = (const char*)glob.ToPointer();
			Marshal::FreeHGlobal(glob);

			glob = Marshal::StringToHGlobalAnsi(username);
			Username = (const char*)glob.ToPointer();
			Marshal::FreeHGlobal(glob);

			glob = Marshal::StringToHGlobalAnsi(password);
			Password = (const char*)glob.ToPointer();
			Marshal::FreeHGlobal(glob);

			return (*_conn)->genericConnectToServer(Url, Username, Password);
		}
	};

	public ref class KeyVEILConnector : public Connector
	{
	public:
		virtual int connect(String^ url, String^ username, String^ password) override
		{
			if (!isReady())
			{
				return connStatus_NoServer;
			}
			tsAscii Url, Username, Password;

			IntPtr glob = Marshal::StringToHGlobalAnsi(url);
			Url = (const char*)glob.ToPointer();
			Marshal::FreeHGlobal(glob);

			glob = Marshal::StringToHGlobalAnsi(username);
			Username = (const char*)glob.ToPointer();
			Marshal::FreeHGlobal(glob);

			glob = Marshal::StringToHGlobalAnsi(password);
			Password = (const char*)glob.ToPointer();
			Marshal::FreeHGlobal(glob);

			return (*_conn)->connect(Url, Username, Password);
		}
	};

}
