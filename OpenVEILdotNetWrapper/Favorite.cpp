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
	Favorite::Favorite() : _dataHolder(nullptr)
	{}
	Favorite::Favorite(std::shared_ptr<IFavorite> _fav) : _dataHolder(new internalWrapper<IFavorite>())
	{
		_dataHolder->set(_fav);
	}
	Favorite::~Favorite()
	{
		release();
	}

	void Favorite::release()
	{
		if (_dataHolder == nullptr)
		{
			delete _dataHolder;
			_dataHolder = nullptr;
		}
	}

	System::Guid Favorite::favoriteId::get()
	{
		if (!isReady())
			return System::Guid::Empty;
		return GUID2Guid(handle()->favoriteId());
	}
	void Favorite::favoriteId::set(System::Guid setTo)
	{
		if (!isReady())
			return;
		handle()->favoriteId(Guid2GUID(setTo));
	}

	System::Guid Favorite::enterpriseId::get()
	{
		if (!isReady())
			return System::Guid::Empty;
		return GUID2Guid(handle()->enterpriseId());
	}
	void Favorite::enterpriseId::set(System::Guid setTo)
	{
		if (!isReady())
			return;
		handle()->enterpriseId(Guid2GUID(setTo));
	}

	String^ Favorite::favoriteName::get()
	{
		if (!isReady())
			return nullptr;
		return gcnew String(handle()->favoriteName().c_str());
	}
	void Favorite::favoriteName::set(String^ setTo)
	{
		if (!isReady())
			return;
		handle()->favoriteName(StringToTsAscii(setTo));
	}

	array<byte>^ Favorite::getTokenSerialNumber()
	{
		if (!isReady())
			return nullptr;
		return tsDataToByteArray(handle()->tokenSerialNumber());
	}
	void Favorite::setTokenSerialNumber(array<byte>^ setTo)
	{
		if (!isReady())
			return;
		handle()->tokenSerialNumber(byteArrayToTsData(setTo));
	}
	array<byte>^ Favorite::getHeaderData()
	{
		if (!isReady())
			return nullptr;
		return tsDataToByteArray(handle()->headerData());
	}
	void Favorite::setHeaderData(array<byte>^ setTo)
	{
		if (!isReady())
			return;
		handle()->headerData(byteArrayToTsData(setTo));
	}

	bool Favorite::encryptFile(Session^ session, String^ sourceFile, bool compress, String^ encryptedFile)
	{
		std::shared_ptr<IFileVEILOperations> fileOps;
		std::shared_ptr<ICmsHeader> header;
		std::shared_ptr<IFileVEILOperationStatus> status;
		tsAscii inputFile(StringToTsAscii(sourceFile));
		tsAscii outputFile(StringToTsAscii(encryptedFile));

		if (!isReady())
			return false;

		if (!InitializeCmsHeader())
			return false;

		if (xp_GetFileAttributes(inputFile) == XP_INVALID_FILE_ATTRIBUTES || xp_IsDirectory(inputFile))
		{
			throw gcnew TecSecRuntimeException(tsAscii() << "File -> " << inputFile.c_str() << " <- does not exist Encrypt operation aborted");
		}

		status = ::ServiceLocator()->Finish<IFileVEILOperationStatus>(new StatusClass());

		if (!(fileOps = CreateFileVEILOperationsObject()) ||
			!(fileOps->SetStatusInterface(status)) ||
			!(fileOps->SetSession(session->handle())))
		{
			throw gcnew TecSecRuntimeException("An error occurred while building the file encryptor.  The OpenVEIL may be damaged.");
		}

		// Create output file name based on the input file name
		if (outputFile.size() == 0)
		{
			outputFile = inputFile;
			outputFile += ".ckm";
		}
		if (!(header = ::ServiceLocator()->get_instance<ICmsHeader>("/CmsHeader")) || !header->FromBytes(handle()->headerData()))
		{
			throw gcnew TecSecRuntimeException("An error occurred while building the encryption header.");
		}

		// Indicate compression is desired.
		if (compress)
		{
			header->SetCompressionType(ct_zLib);
		}
		else
		{
			header->SetCompressionType(ct_None);
		}
		if (header->GetEncryptionAlgorithmID() == TS_ALG_INVALID)
			header->SetEncryptionAlgorithmID(TS_ALG_AES_GCM_256);

		if (!(fileOps->EncryptFileAndStreams(inputFile.c_str(), outputFile.c_str(), header, compress ? ct_zLib : ct_None,
			header->GetEncryptionAlgorithmID(), OIDtoID(header->GetDataHashOID().ToOIDString().c_str()),
			header->HasHeaderSigningPublicKey(), true,
			(Alg2Mode(header->GetEncryptionAlgorithmID()) == CKM_SymMode_GCM ||
				Alg2Mode(header->GetEncryptionAlgorithmID()) == CKM_SymMode_CCM) ?
			TS_FORMAT_CMS_ENC_AUTH : TS_FORMAT_CMS_CT_HASHED,
			false, header->GetPaddingType(), 5000000)))
		{
			//if (!connector->isConnected())
			//{
			//	WARN("The connection to the server was lost.");
			//}
			//return 303;
			throw gcnew TecSecRuntimeException("Encrypt failed");
		}

		return true;
	}
	array<byte>^ Favorite::encryptData(Session^ session, array<byte>^ sourceData, bool compress)
	{
		if (!isReady())
			return nullptr;

		tsData inData(byteArrayToTsData(sourceData));
		tsData encData;

		if (inData.size() == 0)
		{
			return nullptr;
		}

		if (!InitializeCmsHeader())
			return nullptr;

		std::shared_ptr<IFileVEILOperations> fileOps;
		std::shared_ptr<IFileVEILOperationStatus> status;
		std::shared_ptr<ICmsHeader> header;

		if (!session->handle())
		{
			throw gcnew TecSecRuntimeException("Session invalid");
		}

		status = ::ServiceLocator()->Finish<IFileVEILOperationStatus>(new StatusClass());

		if (!(fileOps = CreateFileVEILOperationsObject()) ||
			!(fileOps->SetStatusInterface(status)) ||
			!(fileOps->SetSession(session->handle())))
		{
			throw gcnew TecSecRuntimeException("An error occurred while building the file encryptor.  The CKM Runtime may be damaged.");
		}
		if (!(header = ::ServiceLocator()->get_instance<ICmsHeader>("/CmsHeader")) || !header->FromBytes(handle()->headerData()))
		{
			throw gcnew TecSecRuntimeException("An error occurred while building the encryption header.");
		}

		if (!header)
		{
			throw gcnew TecSecRuntimeException("The favorite is invalid or incomplete.");
		}

		// Indicate compression is desired.
		if (compress)
		{
			header->SetCompressionType(ct_zLib);
		}
		else
		{
			header->SetCompressionType(ct_None);
		}
		if (header->GetEncryptionAlgorithmID() == TS_ALG_INVALID)
			header->SetEncryptionAlgorithmID(TS_ALG_AES_GCM_256);

		if (!(fileOps->EncryptCryptoData(inData, encData, header, compress ? ct_zLib : ct_None,
			header->GetEncryptionAlgorithmID(), OIDtoID(header->GetDataHashOID().ToOIDString().c_str()),
			header->HasHeaderSigningPublicKey(), true,
			(Alg2Mode(header->GetEncryptionAlgorithmID()) == CKM_SymMode_GCM ||
				Alg2Mode(header->GetEncryptionAlgorithmID()) == CKM_SymMode_CCM) ?
			TS_FORMAT_CMS_ENC_AUTH : TS_FORMAT_CMS_CT_HASHED,
			false, header->GetPaddingType(), 5000000)))
		{
			//if (!connector->isConnected())
			//{
			//	//WARN("The connection to the server was lost.");
			//	return 304;
			//}

			//cout << "  Something went wrong on encryption. " << endl;
			//return 305;
			throw gcnew TecSecRuntimeException("Encrypt failed");
		}

		return tsDataToByteArray(encData);
	}
	std::shared_ptr<IFavorite> Favorite::handle() { if (_dataHolder == nullptr) return nullptr; return _dataHolder->get(); }

	bool Favorite::isReady()
	{
		return _dataHolder != nullptr && !!_dataHolder->get();
	}
}
