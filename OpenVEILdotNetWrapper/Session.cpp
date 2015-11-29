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

	Session::Session() : _dataHolder(nullptr)
	{}
	Session::Session(std::shared_ptr<IKeyVEILSession> _sess)
	{
		_dataHolder = new internalWrapper<IKeyVEILSession>();
		_dataHolder->set(_sess);
	}
	Session::~Session()
	{
		if (_dataHolder != nullptr)
		{
			delete _dataHolder;
			_dataHolder = nullptr;
		}
	}

	void Session::release()
	{
		if (_dataHolder != nullptr)
		{
			delete _dataHolder;
			_dataHolder = nullptr;
		}
	}
	void Session::close()
	{
		if (isReady())
			handle()->Close();
	}
	LoginStatus Session::login(String^ pin)
	{
		if (!isReady())
			return LoginStatus::NoServer;
		return (LoginStatus)handle()->Login(StringToTsAscii(pin));
	}
	bool Session::isLoggedIn::get()
	{
		if (!isReady())
			return false;
		return handle()->IsLoggedIn();
	}
	bool Session::logout()
	{
		if (!isReady())
			return false;
		return handle()->Logout();
	}
	//bool GenerateWorkingKey(Asn1::CTS::CkmCombineParameters& params, std::function<bool(Asn1::CTS::CkmCombineParameters&, tsData&)> headerCallback, tsData &WorkingKey);
	//bool RegenerateWorkingKey(Asn1::CTS::CkmCombineParameters& params, tsData &WorkingKey);
	DynamicJsonParser::DynamicJsonObject^ Session::getProfile()
	{
		DynamicJsonParser::DynamicJsonObject^ d = nullptr;

		if (!isReady())
			return nullptr;

		JSONObject obj = handle()->GetProfile()->toJSON();
		JavaScriptSerializer^ serializer = gcnew JavaScriptSerializer();
		serializer->RegisterConverters(gcnew array<JavaScriptConverter^> { gcnew DynamicJsonConverter() });

		d = serializer->Deserialize<DynamicJsonObject^>(gcnew String(obj.ToString().c_str()));
		return d;
	}
	bool Session::isLocked::get()
	{
		if (!isReady())
			return false;
		return handle()->IsLocked();
	}
	int Session::retriesLeft::get()
	{
		if (!isReady())
			return 0;
		return handle()->retriesLeft();
	}
	bool Session::isValid::get()
	{
		if (!isReady())
		{
			return false;
		}
		return handle()->IsValid();
	}
	Session^ Session::duplicate()
	{
		if (!isReady())
			return nullptr;
		return gcnew Session(handle()->Duplicate());
	}
	bool Session::encryptFileUsingFavorite(Favorite^ fav, String^ sourceFile, bool compress, String^ encryptedFile)
	{
		return fav->encryptFile(this, sourceFile, compress, encryptedFile);
	}
	bool Session::decryptFile(String^ encryptedFile, String^ decryptedFile)
	{
		if (!isReady())
			return false;

		if (!InitializeCmsHeader())
			return false;

		std::shared_ptr<IFileVEILOperations> fileOps;
		std::shared_ptr<IFileVEILOperationStatus> status;
		tsAscii inputFile(StringToTsAscii(encryptedFile));
		tsAscii outputFile(StringToTsAscii(decryptedFile));

		if (xp_GetFileAttributes(inputFile) == XP_INVALID_FILE_ATTRIBUTES || xp_IsDirectory(inputFile))
		{
			throw gcnew TecSecRuntimeException(tsAscii() << "File -> " << inputFile << " <- does not exist Decrypt operation aborted");
		}

		status = ::ServiceLocator()->Finish<IFileVEILOperationStatus>(new StatusClass());

		if (!(fileOps = CreateFileVEILOperationsObject()) ||
			!(fileOps->SetStatusInterface(status)) ||
			!(fileOps->SetSession(handle())))
		{
			throw gcnew TecSecRuntimeException("An error occurred while building the file decryptor.  The " VEILCORENAME " may be damaged.");
		}

		if (!fileOps->DecryptFileAndStreams(inputFile, outputFile))
		{
			throw gcnew TecSecRuntimeException("Decrypt failed.");
		}

		return true;
	}
	array<byte>^ Session::encryptDataUsingFavorite(Favorite^ fav, array<byte>^ sourceData, bool compress)
	{
		return fav->encryptData(this, sourceData, compress);
	}
	array<byte>^ Session::decryptData(array<byte>^ encryptedData)
	{
		if (!isReady())
			return nullptr;

		if (!InitializeCmsHeader())
			return nullptr;

		std::shared_ptr<IFileVEILOperations> fileOps;
		std::shared_ptr<IFileVEILOperationStatus> status;
		tsData inData(byteArrayToTsData(encryptedData));
		tsData destData;

		status = ::ServiceLocator()->Finish<IFileVEILOperationStatus>(new StatusClass());

		if (!(fileOps = CreateFileVEILOperationsObject()) ||
			!(fileOps->SetStatusInterface(status)) ||
			!(fileOps->SetSession(handle())))
		{
			throw gcnew TecSecRuntimeException("An error occurred while building the file decryptor.  The OpenVEIL may be damaged.");
		}

		if (!fileOps->DecryptCryptoData(inData, destData))
		{
			//if (!connector->isConnected())
			//{
			//	//WARN("The connection to the server was lost.");
			//	return 103;
			//}
			//return 104;
			throw gcnew TecSecRuntimeException("Decrypt failed.");
		}

		return tsDataToByteArray(destData);
	}

	std::shared_ptr<IKeyVEILSession> Session::handle() { if (_dataHolder == nullptr) return nullptr; return _dataHolder->get(); }
	bool Session::isReady()
	{
		return _dataHolder == nullptr || !!_dataHolder->get();
	}
}