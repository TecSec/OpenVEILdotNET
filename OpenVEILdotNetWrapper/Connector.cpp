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
	Connector::Connector() :
		_dataHolder(new internalWrapper<IKeyVEILConnector>())
	{
		_dataHolder->set(::ServiceLocator()->try_get_instance<IKeyVEILConnector>("/KeyVEILConnector"));
	}
	Connector::~Connector()
	{
		if (_dataHolder != nullptr)
			delete _dataHolder;
		_dataHolder = nullptr;
	}
	void Connector::disconnect()
	{
		if (isConnected())
		{
			handle()->disconnect();
		}
	}
	bool Connector::isConnected()
	{
		if (isReady())
		{
			return handle()->isConnected();
		}
		else
		{
			return false;
		}
	}
	bool Connector::sendJsonRequest(String^ verb, String^ cmd, DynamicJsonObject^ inData, [Out]DynamicJsonObject^% outData, [Out]int% status)
	{
		return sendJsonRequest(verb, cmd, inData->ToString(), outData, status);
	}
	bool Connector::sendJsonRequest(String^ verb, String^ cmd, String^ inData, [Out]DynamicJsonObject^% outData, [Out]int% status)
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

		if (!handle()->sendJsonRequest(Verb, Cmd, inDataTmp, outDataTmp, stat))
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
	bool Connector::sendRequest(String^ verb, String^ cmd, array<byte>^ inData, [Out]array<byte>^% outData, [Out]int% status)
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

		if (!handle()->sendRequest(Verb, Cmd, tmp, outDataTmp, stat))
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
	bool Connector::sendRequestBase64(String^ verb, String^ cmd, String^ inData, [Out]String^% outData, [Out]int% status)
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

		if (!handle()->sendRequest(Verb, Cmd, InData.Base64ToData(), outDataTmp, stat))
		{
			status = stat;
			outData = gcnew String(outDataTmp.ToBase64().c_str());
			return false;
		}

		status = stat;
		outData = gcnew String(outDataTmp.ToBase64().c_str());
		return true;
	}
	std::shared_ptr<IKeyVEILConnector> Connector::handle() { if (_dataHolder == nullptr) return nullptr; return _dataHolder->get(); }

	bool Connector::isReady()
	{
		return _dataHolder != nullptr && !!_dataHolder->get();
	}

	ConnectionStatus GenericConnector::connect(String^ url, String^ username, String^ password)
	{
		if (!isReady())
		{
			return ConnectionStatus::NoServer;
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

		return (ConnectionStatus)handle()->genericConnectToServer(Url, Username, Password);
	}

	ConnectionStatus KeyVEILConnector::connect(String^ url, String^ username, String^ password)
	{
		if (!isReady())
		{
			return ConnectionStatus::NoServer;
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

		return (ConnectionStatus)handle()->connect(Url, Username, Password);
	}
	bool KeyVEILConnector::refresh()
	{
		if (!isReady())
			return false;
		return handle()->refresh();
	}
	int KeyVEILConnector::tokenCount::get()
	{
		if (!isReady())
			return 0;
		return handle()->tokenCount();
	}
	Token^ KeyVEILConnector::tokenByIndex(int index)
	{
		if (!isReady())
			return nullptr;
		return gcnew Token(handle()->token(index));
	}
	Token^ KeyVEILConnector::tokenByName(String^ tokenName)
	{
		if (!isReady())
			return nullptr;
		return gcnew Token(handle()->token(StringToTsAscii(tokenName)));
	}
	Token^ KeyVEILConnector::tokenBySerialNumber(array<byte>^ serialNumber)
	{
		if (!isReady())
			return nullptr;
		return gcnew Token(handle()->token(byteArrayToTsData(serialNumber)));
	}
	Token^ KeyVEILConnector::tokenBySerialNumber(String^ serialNumber)
	{
		if (!isReady())
			return nullptr;
		return gcnew Token(handle()->token(StringToTsAscii(serialNumber).HexToData()));
	}
	Token^ KeyVEILConnector::tokenById(System::Guid id)
	{
		if (!isReady())
			return nullptr;
		return gcnew Token(handle()->token(Guid2GUID(id)));
	}

	int KeyVEILConnector::favoriteCount::get()
	{
		if (!isReady())
			return 0;
		return handle()->favoriteCount();
	}
	Favorite^ KeyVEILConnector::favoriteByIndex(int index)
	{
		if (!isReady())
			return nullptr;
		return gcnew Favorite(handle()->favorite(index));
	}
	Favorite^ KeyVEILConnector::favoriteByName(String^ name)
	{
		if (!isReady())
			return nullptr;
		return gcnew Favorite(handle()->favorite(StringToTsAscii(name)));
	}
	Favorite^ KeyVEILConnector::favoriteById(System::Guid id)
	{
		if (!isReady())
			return nullptr;
		return gcnew Favorite(handle()->favorite(Guid2GUID(id)));
	}
	System::Guid KeyVEILConnector::CreateFavorite(Token^ token, array<byte>^ headerData, String^ name)
	{
		if (!isReady())
			return System::Guid::Empty;
		return GUID2Guid(handle()->CreateFavorite(token->handle()->serialNumber(), byteArrayToTsData(headerData), StringToTsAscii(name)));
	}
	System::Guid KeyVEILConnector::CreateFavorite(System::Guid tokenId, array<byte>^ headerData, String^ name)
	{
		if (!isReady())
			return System::Guid::Empty;
		return GUID2Guid(handle()->CreateFavorite(Guid2GUID(tokenId), byteArrayToTsData(headerData), StringToTsAscii(name)));
	}
	System::Guid KeyVEILConnector::CreateFavorite(array<byte>^ tokenSerial, array<byte>^ headerData, String^ name)
	{
		if (!isReady())
			return System::Guid::Empty;
		return GUID2Guid(handle()->CreateFavorite(byteArrayToTsData(tokenSerial), byteArrayToTsData(headerData), StringToTsAscii(name)));
	}
	bool KeyVEILConnector::DeleteFavorite(System::Guid id)
	{
		if (!isReady())
			return false;
		return handle()->DeleteFavorite(Guid2GUID(id));
	}
	bool KeyVEILConnector::UpdateFavoriteName(System::Guid id, String^ name)
	{
		if (!isReady())
			return false;
		return handle()->UpdateFavoriteName(Guid2GUID(id), StringToTsAscii(name));
	}
	bool KeyVEILConnector::UpdateFavorite(System::Guid id, array<byte>^ data)
	{
		if (!isReady())
			return false;
		return handle()->UpdateFavorite(Guid2GUID(id), byteArrayToTsData(data));
	}
	int KeyVEILConnector::tokenCountForEnterpriseId(System::Guid enterpriseId)
	{
		if (!isReady())
			return 0;
		return handle()->tokenCountForEnterprise(Guid2GUID(enterpriseId));
	}
	Token^ KeyVEILConnector::tokenForEnterprise(System::Guid enterpriseId, int index)
	{
		if (!isReady())
			return nullptr;
		return gcnew Token(handle()->tokenForEnterprise(Guid2GUID(enterpriseId), index));
	}
	int KeyVEILConnector::favoriteCountForEnterprise(System::Guid enterpriseId)
	{
		if (!isReady())
			return false;
		return handle()->favoriteCountForEnterprise(Guid2GUID(enterpriseId));
	}
	Favorite^ KeyVEILConnector::favoriteForEnterprise(System::Guid enterpriseId, int index)
	{
		if (!isReady())
			return nullptr;
		return gcnew Favorite(handle()->favoriteForEnterprise(Guid2GUID(enterpriseId), index));
	}

}