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


namespace OpenVEIL {

	public ref class TecSecRuntimeException : public System::Exception
	{
	public:
		TecSecRuntimeException(String^ msg) : Exception(msg)
		{}
		TecSecRuntimeException(const tsAscii& msg) : Exception(tsAsciiToString(msg))
		{}
	};

	public ref class Environment
	{
	public:
		Environment() {}
		~Environment() {}

		void DispatchEvents() // Call this in the main thread to receive queued up events
		{
			// TODO:  Implement me
		}
		bool InitializeVEIL(bool initiateChangeMonitoring)
		{
			// Forces the core system to initialize
			if (!::ServiceLocator())
				return false;

			if (initiateChangeMonitoring)
			{

			}
			return true;
		}
		bool TerminateVEIL()
		{
			TerminateVEILSystem();
			return true;
		}
	private:
		//std::deque<QueuedVEILEvent> _events;
	};

	ref class Favorite;

	public enum class LoginStatus
	{
		Connected,
		NoServer,
		BadAuth,
	};

	public enum class ConnectionStatus
	{
		Connected,
		NoServer,
		BadAuth,
		WrongProtocol,
		UrlBad,
	};

	public ref class Session
	{
	public:
		Session();
		Session(std::shared_ptr<IKeyVEILSession> _sess);
		~Session();

		void release();
		void close();
		LoginStatus login(String^ pin);
		property bool isLoggedIn { bool get(); }
		bool logout();
		//bool GenerateWorkingKey(Asn1::CTS::CkmCombineParameters& params, std::function<bool(Asn1::CTS::CkmCombineParameters&, tsData&)> headerCallback, tsData &WorkingKey);
		//bool RegenerateWorkingKey(Asn1::CTS::CkmCombineParameters& params, tsData &WorkingKey);
		DynamicJsonParser::DynamicJsonObject^ getProfile();
		property bool isLocked { bool get(); }
		property int retriesLeft { int get(); }
		property bool isValid { bool get(); }
		Session^ duplicate();
		bool encryptFileUsingFavorite(Favorite^ fav, String^ sourceFile, bool compress, String^ encryptedFile);
		bool decryptFile(String^ encryptedFile, String^ decryptedFile);
		array<byte>^ encryptDataUsingFavorite(Favorite^ fav, array<byte>^ sourceData, bool compress);
		array<byte>^ decryptData(array<byte>^ encryptedData);

	internal:
		std::shared_ptr<IKeyVEILSession> handle();

	protected:
		internalWrapper<IKeyVEILSession>* _dataHolder;

		bool isReady();
	};

	public ref class Favorite
	{
	public:
		Favorite();
	internal:
		Favorite(std::shared_ptr<IFavorite> _fav);
	public:
		~Favorite();

		void release();
		property System::Guid favoriteId {System::Guid get(); void set(System::Guid setTo); }
		property System::Guid enterpriseId {System::Guid get(); void set(System::Guid setTo); }
		property String^ favoriteName {String^ get(); void set(String^ setTo); }
		array<byte>^ getTokenSerialNumber();
		void setTokenSerialNumber(array<byte>^ setTo);
		array<byte>^ getHeaderData();
		void setHeaderData(array<byte>^ setTo);

		bool encryptFile(Session^ session, String^ sourceFile, bool compress, String^ encryptedFile);
		array<byte>^ encryptData(Session^ session, array<byte>^ sourceData, bool compress);

	internal:
		std::shared_ptr<IFavorite> handle();

	protected:
		internalWrapper<IFavorite>* _dataHolder;

		bool isReady();
	};

	public ref class Token
	{
	public:
		Token();
	internal:
		Token(std::shared_ptr<IToken> _tok);
	public:
		~Token();

		void release();
		property String^ tokenName { String^ get(); void set(String^ setTo); }
		array<byte>^ serialNumber();
		property System::Guid id { System::Guid get(); }
		property String^ enterpriseName { String ^ get(); }
		property String^ memberName { String ^ get(); }
		property String^ tokenType { String ^ get(); }
		property System::Guid enterpriseId { System::Guid get(); }
		property System::Guid memberId { System::Guid get(); }
		Session^ openSession();

	internal:
		std::shared_ptr<IToken> handle();

	protected:
		internalWrapper<IToken>* _dataHolder;

		bool isReady();
	};

	public ref class Connector abstract
	{
	public:
		Connector();
		virtual ~Connector();
		virtual ConnectionStatus connect(String^ url, String^ username, String^ password) = 0;
		virtual void disconnect();
		virtual bool isConnected();
		virtual bool sendJsonRequest(String^ verb, String^ cmd, DynamicJsonObject^ inData, [Out]DynamicJsonObject^% outData, [Out]int% status);
		virtual bool sendJsonRequest(String^ verb, String^ cmd, String^ inData, [Out]DynamicJsonObject^% outData, [Out]int% status);
		virtual bool sendRequest(String^ verb, String^ cmd, array<byte>^ inData, [Out]array<byte>^% outData, [Out]int% status);
		virtual bool sendRequestBase64(String^ verb, String^ cmd, String^ inData, [Out]String^% outData, [Out]int% status);
		std::shared_ptr<IKeyVEILConnector> handle();

	protected:
		internalWrapper<IKeyVEILConnector>* _dataHolder;

		bool isReady();
	};
	public ref class GenericConnector : public Connector
	{
	public:
		virtual ConnectionStatus connect(String^ url, String^ username, String^ password) override;
	};

	public ref class KeyVEILConnector : public Connector
	{
	public:
		virtual ConnectionStatus connect(String^ url, String^ username, String^ password) override;
		bool refresh();
		property int tokenCount { int get(); }
		Token^ tokenByIndex(int index);
		Token^ tokenByName(String^ tokenName);
		Token^ tokenBySerialNumber(array<byte>^ serialNumber);
		Token^ tokenBySerialNumber(String^ serialNumber);
		Token^ tokenById(System::Guid id);
		property int favoriteCount { int get();}
		Favorite^ favoriteByIndex(int index);
		Favorite^ favoriteByName(String^ name);
		Favorite^ favoriteById(System::Guid id);
		System::Guid CreateFavorite(Token^ token, array<byte>^ headerData, String^ name);
		System::Guid CreateFavorite(System::Guid tokenId, array<byte>^ headerData, String^ name);
		System::Guid CreateFavorite(array<byte>^ tokenSerial, array<byte>^ headerData, String^ name);
		bool DeleteFavorite(System::Guid id);
		bool UpdateFavoriteName(System::Guid id, String^ name);
		bool UpdateFavorite(System::Guid id, array<byte>^ data);
		int tokenCountForEnterpriseId(System::Guid enterpriseId);
		Token^ tokenForEnterprise(System::Guid enterpriseId, int index);
		int favoriteCountForEnterprise(System::Guid enterpriseId);
		Favorite^ favoriteForEnterprise(System::Guid enterpriseId, int index);
	};

}
