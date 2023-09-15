#include <atomic>
#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/multi.h>
#include <system/CFFI.h>
#include <system/CFFIPointer.h>
#include <system/Mutex.h>
#include <system/System.h>
#include <system/ValuePointer.h>
#include <utils/Bytes.h>
#include <string.h>
#include <map>
#include <vector>
#include <memory>


namespace lime {

	Mutex curl_gc_mutex;

        class CURLMultiData;

        class CURLData {
        public:
          std::atomic_int ref_count;
          CURL *curl;
          ValuePointer *readCallback = nullptr;
          ValuePointer *headerCallback = nullptr;
          ValuePointer *seekCallback = nullptr;
          ValuePointer *progressCallback = nullptr;
          ValuePointer *writeCallback = nullptr;
          ValuePointer *xferInfoCallback = nullptr;
		  ValuePointer* haxe_object = nullptr;
          curl_slist *slist = nullptr;
          CURLMultiData *multiHandle = nullptr;

          CURLData(ValuePointer *);

          CURLData(CURLData *in, ValuePointer *);

          ~CURLData();

		 void DecRef();

          static CURLData *fromCFFI(value val);

          static CURLData *fromCFFI(HL_CFFIPointer *val);

          static void gc_val(value val);

          static void gc_hl(HL_CFFIPointer *val);

          value allocCFFI();

          HL_CFFIPointer *allocCFFI_HL();
        };

        class CURLMultiData {
        public:
          //   std::atomic_int ref_count = 0;
          CURLM *curlm;
		  Mutex map_mutex;
          std::map<CURL *, CURLData *> handles;
		  int runningHandles = 0;

          CURLMultiData() { curlm = curl_multi_init(); }

		  ~CURLMultiData() {
			curl_multi_cleanup(curlm);
			map_mutex.Lock();
			for (auto it = handles.begin (); it != handles.end (); ++it) {
				it->second->multiHandle = nullptr;
				it->second->DecRef();
			}
			map_mutex.Unlock();
		  }

          CURLMcode AddHandle(CURLData *data) {
			data->ref_count++;
			map_mutex.Lock();
            handles[data->curl] = data;
            map_mutex.Unlock();
            data->multiHandle = this;
            return curl_multi_add_handle(curlm, data->curl);
          }

		  CURLMcode RemoveHandle(CURLData *data) {
			data->DecRef();
			map_mutex.Lock();
			handles.erase(data->curl);
			map_mutex.Unlock();
			data->multiHandle = nullptr;
			return curl_multi_remove_handle(curlm, data->curl);
		  }

		  CURLMcode Perform() {
			return curl_multi_perform(curlm, &runningHandles);
		  }


          static CURLMultiData *fromCFFI(value val) {
            return (CURLMultiData *)val_data(val);
          }

          static CURLMultiData *fromCFFI(HL_CFFIPointer *val) {
            return (CURLMultiData *)val->ptr;
          }

          static void gc_val(value val) {
            val_gc(val, nullptr);
            CURLMultiData *data = (CURLMultiData *)val_data(val);
            delete data;
          }

          static void gc_hl(HL_CFFIPointer *val) {
            val->finalizer = NULL;
            CURLMultiData *data = (CURLMultiData *)val->ptr;
            delete data;
          }

          value allocCFFI() {
            value v = cffi::alloc_pointer(this);
            val_gc(v, gc_val);
            return v;
          }

          HL_CFFIPointer *allocCFFI_HL() {
            HL_CFFIPointer *ptr =
                (HL_CFFIPointer *)hl_gc_alloc_finalizer(sizeof(HL_CFFIPointer));
            ptr->finalizer = (void *)gc_hl;
			ptr->ptr = this;
            return ptr;
          }
        };

        CURLData::CURLData(ValuePointer *obj) : haxe_object(obj) { curl = curl_easy_init(); }

        CURLData::CURLData(CURLData *in,ValuePointer *obj) : haxe_object(obj) {
          curl = curl_easy_duphandle(in->curl);
          headerCallback =
              in->headerCallback ? in->headerCallback->Clone() : nullptr;
          readCallback =
              in->readCallback ? in->readCallback->Clone() : nullptr;
          seekCallback =
              in->seekCallback ? in->seekCallback->Clone() : nullptr;
          progressCallback =
              in->progressCallback ? in->progressCallback->Clone() : nullptr;
          writeCallback =
              in->writeCallback ? in->writeCallback->Clone() : nullptr;
          xferInfoCallback =
              in->xferInfoCallback ? in->xferInfoCallback->Clone() : nullptr;
        }

        CURLData::~CURLData() {
          delete headerCallback;
          delete progressCallback;
          delete writeCallback;
          if (slist != nullptr) {
            curl_slist_free_all(slist);
          }
          if (multiHandle) {
            multiHandle->map_mutex.Lock();
            curl_multi_remove_handle(multiHandle->curlm, curl);
            multiHandle->handles.erase(curl);
            multiHandle->map_mutex.Unlock();
          }
          curl_easy_cleanup(curl);
        }

		void CURLData::DecRef() {
			this->ref_count--;
          if (this->ref_count <= 0) {
            delete this;
          }
		}

        CURLData *CURLData::fromCFFI(value val) {
          return (CURLData *)val_data(val);
        }

        CURLData *CURLData::fromCFFI(HL_CFFIPointer *val) {
          return (CURLData *)val->ptr;
        }

        void CURLData::gc_val(value val) {
          val_gc(val, nullptr);
          CURLData *data = (CURLData *)val_data(val);
          data->DecRef();
        }

        void CURLData::gc_hl(HL_CFFIPointer *val) {
          val->finalizer = NULL;
          CURLData *data = (CURLData *)val->ptr;
          data->DecRef();
        }

        value CURLData::allocCFFI() {
          this->ref_count++;
          value v = cffi::alloc_pointer(this);
          val_gc(v, gc_val);
          return v;
        }

        HL_CFFIPointer *CURLData::allocCFFI_HL() {
          this->ref_count++;
          HL_CFFIPointer *ptr =
              (HL_CFFIPointer *)hl_gc_alloc_finalizer(sizeof(HL_CFFIPointer));
          ptr->finalizer = (void *)gc_hl;
		  ptr->ptr = this;
          return ptr;
        }

	void lime_curl_easy_cleanup (value handle) {
		delete CURLData::fromCFFI(handle);
	}


	HL_PRIM void HL_NAME(hl_curl_easy_cleanup) (HL_CFFIPointer* handle) {
		delete CURLData::fromCFFI(handle);
	}


	value lime_curl_easy_duphandle (value handle, value haxe_object) {

		CURLData *data = CURLData::fromCFFI(handle);
		return (new CURLData(data, new ValuePointer(haxe_object)))->allocCFFI();

	}


	HL_PRIM HL_CFFIPointer* HL_NAME(hl_curl_easy_duphandle) (HL_CFFIPointer* handle, vdynamic *haxe_object) {

		CURLData *data = CURLData::fromCFFI(handle);
		return (new CURLData(data, new ValuePointer(haxe_object)))->allocCFFI_HL();


	}


	value lime_curl_easy_escape (value curl, HxString url, int length) {

		char* result = curl_easy_escape ((CURL*)val_data(curl), url.__s, length);
		return result ? alloc_string (result) : alloc_null ();

	}


	HL_PRIM vbyte* HL_NAME(hl_curl_easy_escape) (HL_CFFIPointer* curl, hl_vstring* url, int length) {

		char* result = curl_easy_escape ((CURL*)curl->ptr, url ? hl_to_utf8 (url->bytes) : NULL, length);
		return (vbyte*)result;

	}


	void lime_curl_easy_flush (value easy_handle) {

	}


	HL_PRIM void HL_NAME(hl_curl_easy_flush) (HL_CFFIPointer* easy_handle) {

	}


	value lime_curl_easy_getinfo (value curl, int info) {

		CURLData *data = CURLData::fromCFFI(curl);
		CURLcode code = CURLE_OK;
		CURL* handle = data->curl;
		CURLINFO type = (CURLINFO)info;

		switch (type) {

			case CURLINFO_EFFECTIVE_URL:
			case CURLINFO_REDIRECT_URL:
			case CURLINFO_CONTENT_TYPE:
			case CURLINFO_PRIVATE:
			case CURLINFO_PRIMARY_IP:
			case CURLINFO_LOCAL_IP:
			case CURLINFO_FTP_ENTRY_PATH:
			case CURLINFO_RTSP_SESSION_ID:
			case CURLINFO_SCHEME:

				char stringValue;
				code = curl_easy_getinfo (handle, type, &stringValue);
				return alloc_string (&stringValue);
				break;

			case CURLINFO_RESPONSE_CODE:
			case CURLINFO_HTTP_CONNECTCODE:
			case CURLINFO_FILETIME:
			case CURLINFO_REDIRECT_COUNT:
			case CURLINFO_HEADER_SIZE:
			case CURLINFO_REQUEST_SIZE:
			case CURLINFO_SSL_VERIFYRESULT:
			case CURLINFO_HTTPAUTH_AVAIL:
			case CURLINFO_PROXYAUTH_AVAIL:
			case CURLINFO_OS_ERRNO:
			case CURLINFO_NUM_CONNECTS:
			case CURLINFO_PRIMARY_PORT:
			case CURLINFO_LOCAL_PORT:
			case CURLINFO_LASTSOCKET:
			case CURLINFO_CONDITION_UNMET:
			case CURLINFO_RTSP_CLIENT_CSEQ:
			case CURLINFO_RTSP_SERVER_CSEQ:
			case CURLINFO_RTSP_CSEQ_RECV:
			case CURLINFO_HTTP_VERSION:
			case CURLINFO_PROXY_SSL_VERIFYRESULT:
			case CURLINFO_PROTOCOL:
			case CURLINFO_SIZE_UPLOAD_T: // TODO: These should be larger
			case CURLINFO_SIZE_DOWNLOAD_T:
			case CURLINFO_SPEED_DOWNLOAD_T:
			case CURLINFO_SPEED_UPLOAD_T:
			case CURLINFO_CONTENT_LENGTH_DOWNLOAD_T:
			case CURLINFO_CONTENT_LENGTH_UPLOAD_T:

				long intValue;
				code = curl_easy_getinfo (handle, type, &intValue);
				return alloc_int (intValue);
				break;

			case CURLINFO_TOTAL_TIME:
			case CURLINFO_NAMELOOKUP_TIME:
			case CURLINFO_CONNECT_TIME:
			case CURLINFO_APPCONNECT_TIME:
			case CURLINFO_PRETRANSFER_TIME:
			case CURLINFO_STARTTRANSFER_TIME:
			case CURLINFO_REDIRECT_TIME:
			case CURLINFO_SIZE_UPLOAD:
			case CURLINFO_SIZE_DOWNLOAD:
			case CURLINFO_SPEED_DOWNLOAD:
			case CURLINFO_SPEED_UPLOAD:
			case CURLINFO_CONTENT_LENGTH_DOWNLOAD:
			case CURLINFO_CONTENT_LENGTH_UPLOAD:

				double floatValue;
				code = curl_easy_getinfo (handle, type, &floatValue);
				return alloc_float (floatValue);
				break;

			case CURLINFO_COOKIELIST:
			{
				struct curl_slist *cookies;
				code = curl_easy_getinfo(handle, CURLINFO_COOKIELIST, &cookies);
				struct curl_slist *each = cookies;
				value result = alloc_array(0);
				while (each) {
					val_array_push(result, alloc_string(each->data));
					each = each->next;
				}
				curl_slist_free_all(cookies);
				return result;
				break;
			}

			case CURLINFO_SSL_ENGINES:
			case CURLINFO_CERTINFO:
			case CURLINFO_TLS_SESSION:
			case CURLINFO_TLS_SSL_PTR:
			case CURLINFO_ACTIVESOCKET:

				// TODO

				break;

			case CURLINFO_NONE:
			case CURLINFO_LASTONE:

				// ignore

				break;


		}

		return alloc_null ();

	}


	HL_PRIM vdynamic* HL_NAME(hl_curl_easy_getinfo) (HL_CFFIPointer* curl, int info) {

		CURLData *data = CURLData::fromCFFI(curl);
		CURLcode code = CURLE_OK;
		CURL* handle = data->curl;
		CURLINFO type = (CURLINFO)info;

		int size;
		vdynamic* result = NULL;

		switch (type) {

			case CURLINFO_EFFECTIVE_URL:
			case CURLINFO_REDIRECT_URL:
			case CURLINFO_CONTENT_TYPE:
			case CURLINFO_PRIVATE:
			case CURLINFO_PRIMARY_IP:
			case CURLINFO_LOCAL_IP:
			case CURLINFO_FTP_ENTRY_PATH:
			case CURLINFO_RTSP_SESSION_ID:
			case CURLINFO_SCHEME:
			{
				char stringValue;
				code = curl_easy_getinfo (handle, type, &stringValue);

				int size = strlen (&stringValue) + 1;
				char* val = (char*)malloc (size);
				memcpy (val, &stringValue, size);

				result = hl_alloc_dynamic (&hlt_bytes);
				result->v.b = val;
				return result;
				break;
			}

			case CURLINFO_RESPONSE_CODE:
			case CURLINFO_HTTP_CONNECTCODE:
			case CURLINFO_FILETIME:
			case CURLINFO_REDIRECT_COUNT:
			case CURLINFO_HEADER_SIZE:
			case CURLINFO_REQUEST_SIZE:
			case CURLINFO_SSL_VERIFYRESULT:
			case CURLINFO_HTTPAUTH_AVAIL:
			case CURLINFO_PROXYAUTH_AVAIL:
			case CURLINFO_OS_ERRNO:
			case CURLINFO_NUM_CONNECTS:
			case CURLINFO_PRIMARY_PORT:
			case CURLINFO_LOCAL_PORT:
			case CURLINFO_LASTSOCKET:
			case CURLINFO_CONDITION_UNMET:
			case CURLINFO_RTSP_CLIENT_CSEQ:
			case CURLINFO_RTSP_SERVER_CSEQ:
			case CURLINFO_RTSP_CSEQ_RECV:
			case CURLINFO_HTTP_VERSION:
			case CURLINFO_PROXY_SSL_VERIFYRESULT:
			case CURLINFO_PROTOCOL:
			case CURLINFO_SIZE_UPLOAD_T: // TODO: These should be larger
			case CURLINFO_SIZE_DOWNLOAD_T:
			case CURLINFO_SPEED_DOWNLOAD_T:
			case CURLINFO_SPEED_UPLOAD_T:
			case CURLINFO_CONTENT_LENGTH_DOWNLOAD_T:
			case CURLINFO_CONTENT_LENGTH_UPLOAD_T:
			{
				long intValue;
				code = curl_easy_getinfo (handle, type, &intValue);

				result = hl_alloc_dynamic (&hlt_i32);
				result->v.i = intValue;
				return result;
				break;
			}

			case CURLINFO_TOTAL_TIME:
			case CURLINFO_NAMELOOKUP_TIME:
			case CURLINFO_CONNECT_TIME:
			case CURLINFO_APPCONNECT_TIME:
			case CURLINFO_PRETRANSFER_TIME:
			case CURLINFO_STARTTRANSFER_TIME:
			case CURLINFO_REDIRECT_TIME:
			case CURLINFO_SIZE_UPLOAD:
			case CURLINFO_SIZE_DOWNLOAD:
			case CURLINFO_SPEED_DOWNLOAD:
			case CURLINFO_SPEED_UPLOAD:
			case CURLINFO_CONTENT_LENGTH_DOWNLOAD:
			case CURLINFO_CONTENT_LENGTH_UPLOAD:
			{
				double floatValue;
				code = curl_easy_getinfo (handle, type, &floatValue);

				result = hl_alloc_dynamic (&hlt_f64);
				result->v.d = floatValue;
				return result;
				break;
			}

			case CURLINFO_SSL_ENGINES:
			case CURLINFO_COOKIELIST:
			case CURLINFO_CERTINFO:
			case CURLINFO_TLS_SESSION:
			case CURLINFO_TLS_SSL_PTR:
			case CURLINFO_ACTIVESOCKET:

				// TODO

				break;

			case CURLINFO_NONE:
			case CURLINFO_LASTONE:

				// ignore

				break;


		}

		return NULL;

	}

	value lime_curl_easy_init (value obj) {
		return (new CURLData(new ValuePointer(obj)))->allocCFFI();
	}


	HL_PRIM HL_CFFIPointer* HL_NAME(hl_curl_easy_init) (vdynamic *obj) {
		return (new CURLData(new ValuePointer(obj)))->allocCFFI_HL();
	}


	int lime_curl_easy_pause (value handle, int bitmask) {

		return curl_easy_pause (CURLData::fromCFFI(handle)->curl, bitmask);

	}


	HL_PRIM int HL_NAME(hl_curl_easy_pause) (HL_CFFIPointer* handle, int bitmask) {

		return curl_easy_pause (CURLData::fromCFFI(handle)->curl, bitmask);

	}


	int lime_curl_easy_perform (value easy_handle) {

		int code;
		code = curl_easy_perform (CURLData::fromCFFI(easy_handle)->curl);
		return code;

	}


	HL_PRIM int HL_NAME(hl_curl_easy_perform) (HL_CFFIPointer* easy_handle) {

		int code;
		code = curl_easy_perform (CURLData::fromCFFI(easy_handle)->curl);
		return code;

	}


	int lime_curl_easy_recv (value curl, value buffer, int buflen, int n) {

		// TODO

		return 0;

	}


	HL_PRIM int HL_NAME(hl_curl_easy_recv) (HL_CFFIPointer* curl, double buffer, int buflen, int n) {

		// TODO

		return 0;

	}


	void lime_curl_easy_reset (value handle) {

		curl_easy_reset (CURLData::fromCFFI(handle)->curl);

	}


	HL_PRIM void HL_NAME(hl_curl_easy_reset) (HL_CFFIPointer* curl) {

		curl_easy_reset (CURLData::fromCFFI(curl)->curl);

	}


	int lime_curl_easy_send (value curl, value buffer, int buflen, int n) {

		// TODO

		return 0;

	}


	HL_PRIM int HL_NAME(hl_curl_easy_send) (HL_CFFIPointer* curl, double buffer, int buflen, int n) {

		// TODO

		return 0;

	}


	static vdynamic *hl_alloc_int(int i) {
		vdynamic *v = hl_alloc_dynamic(&hlt_i32);
		v->v.i = i;
		return v;
	}

	static vdynamic *hl_alloc_double(double d) {
		vdynamic *v = hl_alloc_dynamic(&hlt_f64);
		v->v.d = d;
		return v;
	}

	static int hl_dyn_to_i(vdynamic *d) {
		if(d) {
			return d->v.i;
		} else {
			return 0;
		}
	}


	static size_t header_callback (void *ptr, size_t size, size_t nmemb, void *userp) {

		// std::vector<char*>* values = headerValues[userp];

		// if (size * nmemb > 0) {

		// 	char* data = (char*)malloc (size * nmemb + 1);
		// 	memcpy (data, ptr, size * nmemb);
		// 	data[size * nmemb] = '\0';
		// 	values->push_back (data);

		// }

		return size * nmemb;

	}


	static size_t write_callback (void *ptr, size_t size, size_t nmemb, void *userp) {
		CURLData *data = (CURLData*)userp;

		if(!data || !data->writeCallback || !data->writeCallback->Get()) {
			return 0;
		}

		if(data->writeCallback->IsHLValue()) {
			vclosure *cb = (vclosure*)data->writeCallback->Get();
			size_t len = size * nmemb;
			vbyte *data = hl_alloc_bytes(len);
			memcpy(data, ptr, len);
			vdynamic *db = hl_alloc_dynamic(&hlt_bytes);
			db->v.bytes = data;
			vdynamic *args[] = {
				db,
				hl_alloc_int(len),
			};
			return hl_dyn_to_i(hl_dyn_call(cb, args, 2));
		} else {
			size_t len = size * nmemb;
			buffer buf = alloc_buffer_len(len);
			buffer_append_sub(buf, (const char*)ptr, len);
			value val = buffer_val(buf);
			value cb = (value)data->writeCallback->Get();
			value args[] = {
				val,
				alloc_int(len),
			};
			return val_int(val_callN(cb, args, 2));
		}
	}

	static int seek_callback (void *userp, curl_off_t offset, int origin) {
		CURLData *data = (CURLData*)userp;

		if(!data || !data->seekCallback) {
			return 0;
		}

		if(!data->seekCallback->Get()) {
			return 0;
		}

		if(data->seekCallback->IsHLValue()) {
			vclosure *cb = (vclosure*)data->seekCallback->Get();
						vdynamic *args[] = {
				hl_alloc_int(offset),
				hl_alloc_int(origin),
			};
			return hl_dyn_to_i(hl_dyn_call(cb, args, 2));
		} else {
			value cb  = (value)data->seekCallback->Get();
			value args[] = {
				alloc_int(offset),
				alloc_int(origin),
			};
			return val_int(val_callN(cb, args, 2));
		}
	}

	static size_t read_callback (void *buffer, size_t size, size_t nmemb, void *userp) {
		// TODO
		return 0;
	}

	static int progress_callback (void *userp, double dltotal, double dlnow, double ultotal, double ulnow) {

		CURLData *data = (CURLData*)userp;

		if(!data && !data->progressCallback) {
			return 0;
		}

		if(!data->progressCallback->Get()) {
			return 0;
		}

		if(data->progressCallback->IsHLValue()) {
			vclosure *cb = (vclosure*)data->progressCallback->Get();
			vdynamic *args[] = {
				hl_alloc_double(dltotal),
				hl_alloc_double(dlnow),
				hl_alloc_double(ultotal),
				hl_alloc_double(ulnow),
			};
			return hl_dyn_to_i(hl_dyn_call(cb, args, 4));
		} else {
			value cb  = (value)data->progressCallback->Get();
			value args[] = {
				alloc_float(dltotal),
				alloc_float(dlnow),
				alloc_float(ultotal),
				alloc_float(ulnow),
			};
			return val_int(val_callN(cb, args, 4));
		}

	}


	static int xferinfo_callback (void *userp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {

		CURLData *data = (CURLData*)userp;

		if(!data && !data->xferInfoCallback) {
			return 0;
		}

		if(!data->xferInfoCallback->Get()) {
			return 0;
		}

		if(data->xferInfoCallback->IsHLValue()) {
			vclosure *cb = (vclosure*)data->xferInfoCallback->Get();
			vdynamic *args[] = {
				hl_alloc_int(dltotal),
				hl_alloc_int(dlnow),
				hl_alloc_int(ultotal),
				hl_alloc_int(ulnow),
			};
			return hl_dyn_to_i(hl_dyn_call(cb, args, 2));
        } else {
			value cb  = (value)data->xferInfoCallback->Get();
			value args[] = {
				alloc_int(dltotal),
				alloc_int(dlnow),
				alloc_int(ultotal),
				alloc_int(ulnow),
			};
			return val_int(val_callN(cb, args, 4));
		}

	}


	int lime_curl_easy_setopt (value handle, int option, value parameter, value bytes) {

		CURLData *data = CURLData::fromCFFI(handle);
		CURLcode code = CURLE_OK;
		// CURL* easy_handle = (CURL*)val_data(handle);
		CURLoption type = (CURLoption)option;

		switch (type) {

			case CURLOPT_VERBOSE:
			case CURLOPT_HEADER:
			case CURLOPT_NOPROGRESS:
			case CURLOPT_NOSIGNAL:
			case CURLOPT_WILDCARDMATCH:
			case CURLOPT_FAILONERROR:
			case CURLOPT_DNS_USE_GLOBAL_CACHE:
			case CURLOPT_TCP_NODELAY:
			case CURLOPT_TCP_KEEPALIVE:
			case CURLOPT_SASL_IR:
			case CURLOPT_AUTOREFERER:
			case CURLOPT_TRANSFER_ENCODING:
			case CURLOPT_FOLLOWLOCATION:
			case CURLOPT_UNRESTRICTED_AUTH:
			case CURLOPT_PUT:
			case CURLOPT_POST:
			case CURLOPT_COOKIESESSION:
			case CURLOPT_HTTPGET:
			case CURLOPT_IGNORE_CONTENT_LENGTH:
			case CURLOPT_HTTP_CONTENT_DECODING:
			case CURLOPT_HTTP_TRANSFER_DECODING:
			case CURLOPT_DIRLISTONLY:
			case CURLOPT_APPEND:
			case CURLOPT_FTP_USE_EPRT:
			case CURLOPT_FTP_USE_EPSV:
			case CURLOPT_FTP_USE_PRET:
			case CURLOPT_FTP_CREATE_MISSING_DIRS:
			case CURLOPT_FTP_SKIP_PASV_IP:
			case CURLOPT_TRANSFERTEXT:
			case CURLOPT_CRLF:
			case CURLOPT_NOBODY:
			case CURLOPT_UPLOAD:
			case CURLOPT_FRESH_CONNECT:
			case CURLOPT_FORBID_REUSE:
			case CURLOPT_CONNECT_ONLY:
			case CURLOPT_USE_SSL:
			//case CURLOPT_SSL_ENABLE_ALPN:
			//case CURLOPT_SSL_ENABLE_NPN:
			case CURLOPT_SSL_VERIFYPEER:
			case CURLOPT_SSL_SESSIONID_CACHE:
			case CURLOPT_TCP_FASTOPEN:
			case CURLOPT_KEEP_SENDING_ON_ERROR:
			case CURLOPT_PATH_AS_IS:
			case CURLOPT_SSL_VERIFYSTATUS:
			case CURLOPT_SSL_FALSESTART:
			case CURLOPT_PIPEWAIT:
			case CURLOPT_TFTP_NO_OPTIONS:
			case CURLOPT_SUPPRESS_CONNECT_HEADERS:
			case CURLOPT_SSH_COMPRESSION:

				code = curl_easy_setopt (data->curl, type, val_bool (parameter));
				break;

			case CURLOPT_SSL_VERIFYHOST:
			case CURLOPT_PROTOCOLS:
			case CURLOPT_REDIR_PROTOCOLS:
			case CURLOPT_PROXYPORT:
			case CURLOPT_PROXYTYPE:
			case CURLOPT_HTTPPROXYTUNNEL:
			case CURLOPT_SOCKS5_GSSAPI_NEC:
			case CURLOPT_LOCALPORT:
			case CURLOPT_LOCALPORTRANGE:
			case CURLOPT_DNS_CACHE_TIMEOUT:
			case CURLOPT_BUFFERSIZE:
			case CURLOPT_PORT:
			case CURLOPT_ADDRESS_SCOPE:
			case CURLOPT_TCP_KEEPIDLE:
			case CURLOPT_TCP_KEEPINTVL:
			case CURLOPT_NETRC:
			case CURLOPT_HTTPAUTH:
			case CURLOPT_PROXYAUTH:
			case CURLOPT_MAXREDIRS:
			case CURLOPT_POSTREDIR:
			case CURLOPT_POSTFIELDSIZE:
			//case CURLOPT_HEADEROPT:
			case CURLOPT_HTTP_VERSION:
			//case CURLOPT_EXPECT_100_TIMEOUT_MS:
			case CURLOPT_TFTP_BLKSIZE:
			case CURLOPT_FTP_RESPONSE_TIMEOUT:
			case CURLOPT_FTPSSLAUTH:
			case CURLOPT_FTP_SSL_CCC:
			case CURLOPT_FTP_FILEMETHOD:
			case CURLOPT_RTSP_REQUEST:
			case CURLOPT_RTSP_CLIENT_CSEQ:
			case CURLOPT_RTSP_SERVER_CSEQ:
			case CURLOPT_PROXY_TRANSFER_MODE:
			case CURLOPT_RESUME_FROM:
			case CURLOPT_FILETIME:
			case CURLOPT_INFILESIZE:
			case CURLOPT_MAXFILESIZE:
			case CURLOPT_TIMECONDITION:
			case CURLOPT_TIMEVALUE:
			case CURLOPT_TIMEOUT:
			case CURLOPT_TIMEOUT_MS:
			case CURLOPT_LOW_SPEED_LIMIT:
			case CURLOPT_LOW_SPEED_TIME:
			case CURLOPT_MAXCONNECTS:
			case CURLOPT_CONNECTTIMEOUT:
			case CURLOPT_CONNECTTIMEOUT_MS:
			case CURLOPT_IPRESOLVE:
			case CURLOPT_ACCEPTTIMEOUT_MS:
			case CURLOPT_SSLENGINE_DEFAULT:
			case CURLOPT_SSLVERSION:
			case CURLOPT_CERTINFO:
			case CURLOPT_SSL_OPTIONS:
			case CURLOPT_GSSAPI_DELEGATION:
			case CURLOPT_SSH_AUTH_TYPES:
			case CURLOPT_NEW_FILE_PERMS:
			case CURLOPT_NEW_DIRECTORY_PERMS:
			case CURLOPT_STREAM_WEIGHT:
			case CURLOPT_PROXY_SSL_VERIFYPEER:
			case CURLOPT_PROXY_SSL_VERIFYHOST:
			case CURLOPT_PROXY_SSLVERSION:
			case CURLOPT_PROXY_SSL_OPTIONS:
			case CURLOPT_SOCKS5_AUTH:

				code = curl_easy_setopt (data->curl, type, val_int (parameter));
				break;

			case CURLOPT_POSTFIELDSIZE_LARGE:
			case CURLOPT_RESUME_FROM_LARGE:
			case CURLOPT_INFILESIZE_LARGE:
			case CURLOPT_MAXFILESIZE_LARGE:
			case CURLOPT_MAX_SEND_SPEED_LARGE:
			case CURLOPT_MAX_RECV_SPEED_LARGE:

				code = curl_easy_setopt (data->curl, type, val_float (parameter));
				break;

			case CURLOPT_ERRORBUFFER:
			case CURLOPT_URL:
			case CURLOPT_PROXY:
			case CURLOPT_NOPROXY:
			case CURLOPT_SOCKS5_GSSAPI_SERVICE:
			case CURLOPT_INTERFACE:
			case CURLOPT_NETRC_FILE:
			case CURLOPT_USERPWD:
			case CURLOPT_PROXYUSERPWD:
			case CURLOPT_USERNAME:
			case CURLOPT_PASSWORD:
			case CURLOPT_LOGIN_OPTIONS:
			case CURLOPT_PROXYUSERNAME:
			case CURLOPT_PROXYPASSWORD:
			case CURLOPT_TLSAUTH_USERNAME:
			case CURLOPT_TLSAUTH_PASSWORD:
			case CURLOPT_XOAUTH2_BEARER:
			case CURLOPT_ACCEPT_ENCODING:
			case CURLOPT_POSTFIELDS:
			case CURLOPT_COPYPOSTFIELDS:
			case CURLOPT_REFERER:
			case CURLOPT_USERAGENT:
			case CURLOPT_COOKIE:
			case CURLOPT_COOKIEFILE:
			case CURLOPT_COOKIEJAR:
			case CURLOPT_COOKIELIST:
			case CURLOPT_MAIL_FROM:
			case CURLOPT_MAIL_AUTH:
			case CURLOPT_FTPPORT:
			case CURLOPT_FTP_ALTERNATIVE_TO_USER:
			case CURLOPT_FTP_ACCOUNT:
			case CURLOPT_RTSP_SESSION_ID:
			case CURLOPT_RTSP_STREAM_URI:
			case CURLOPT_RTSP_TRANSPORT:
			case CURLOPT_RANGE:
			case CURLOPT_CUSTOMREQUEST:
			case CURLOPT_DNS_INTERFACE:
			case CURLOPT_DNS_LOCAL_IP4:
			case CURLOPT_DNS_LOCAL_IP6:
			case CURLOPT_SSLCERT:
			case CURLOPT_SSLCERTTYPE:
			case CURLOPT_SSLKEY:
			case CURLOPT_SSLKEYTYPE:
			case CURLOPT_KEYPASSWD:
			case CURLOPT_SSLENGINE:
			case CURLOPT_CAINFO:
			case CURLOPT_ISSUERCERT:
			case CURLOPT_CAPATH:
			case CURLOPT_CRLFILE:
			case CURLOPT_RANDOM_FILE:
			case CURLOPT_EGDSOCKET:
			case CURLOPT_SSL_CIPHER_LIST:
			case CURLOPT_KRBLEVEL:
			case CURLOPT_SSH_HOST_PUBLIC_KEY_MD5:
			case CURLOPT_SSH_PUBLIC_KEYFILE:
			case CURLOPT_SSH_PRIVATE_KEYFILE:
			case CURLOPT_SSH_KNOWNHOSTS:
			case CURLOPT_PINNEDPUBLICKEY:
			case CURLOPT_UNIX_SOCKET_PATH:
			case CURLOPT_PROXY_SERVICE_NAME:
			case CURLOPT_SERVICE_NAME:
			case CURLOPT_DEFAULT_PROTOCOL:
			case CURLOPT_PROXY_CAINFO:
			case CURLOPT_PROXY_CAPATH:
			case CURLOPT_PROXY_TLSAUTH_USERNAME:
			case CURLOPT_PROXY_TLSAUTH_PASSWORD:
			case CURLOPT_PROXY_TLSAUTH_TYPE:
			case CURLOPT_PROXY_SSLCERT:
			case CURLOPT_PROXY_SSLCERTTYPE:
			case CURLOPT_PROXY_SSLKEY:
			case CURLOPT_PROXY_SSLKEYTYPE:
			case CURLOPT_PROXY_KEYPASSWD:
			case CURLOPT_PROXY_SSL_CIPHER_LIST:
			case CURLOPT_PROXY_CRLFILE:
			case CURLOPT_PRE_PROXY:
			case CURLOPT_PROXY_PINNEDPUBLICKEY:
			case CURLOPT_ABSTRACT_UNIX_SOCKET:
			case CURLOPT_REQUEST_TARGET:

				code = curl_easy_setopt (data->curl, type, val_string (parameter));
				break;

			case CURLOPT_IOCTLFUNCTION:
			case CURLOPT_IOCTLDATA:
			case CURLOPT_SOCKOPTFUNCTION:
			case CURLOPT_SOCKOPTDATA:
			case CURLOPT_OPENSOCKETFUNCTION:
			case CURLOPT_OPENSOCKETDATA:
			case CURLOPT_CLOSESOCKETFUNCTION:
			case CURLOPT_CLOSESOCKETDATA:
			case CURLOPT_DEBUGFUNCTION:
			case CURLOPT_DEBUGDATA:
			case CURLOPT_SSL_CTX_FUNCTION:
			case CURLOPT_SSL_CTX_DATA:
			case CURLOPT_CONV_TO_NETWORK_FUNCTION:
			case CURLOPT_CONV_FROM_NETWORK_FUNCTION:
			case CURLOPT_CONV_FROM_UTF8_FUNCTION:
			case CURLOPT_INTERLEAVEFUNCTION:
			case CURLOPT_INTERLEAVEDATA:
			case CURLOPT_CHUNK_BGN_FUNCTION:
			case CURLOPT_CHUNK_END_FUNCTION:
			case CURLOPT_CHUNK_DATA:
			case CURLOPT_FNMATCH_FUNCTION:
			case CURLOPT_FNMATCH_DATA:
			case CURLOPT_STDERR:
			case CURLOPT_HTTPPOST:
			//case CURLOPT_PROXYHEADER:
			case CURLOPT_HTTP200ALIASES:
			case CURLOPT_MAIL_RCPT:
			case CURLOPT_QUOTE:
			case CURLOPT_POSTQUOTE:
			case CURLOPT_PREQUOTE:
			case CURLOPT_RESOLVE:
			case CURLOPT_SSH_KEYFUNCTION:
			case CURLOPT_SSH_KEYDATA:
			case CURLOPT_PRIVATE:
			case CURLOPT_SHARE:
			case CURLOPT_TELNETOPTIONS:
			case CURLOPT_STREAM_DEPENDS:
			case CURLOPT_STREAM_DEPENDS_E:
			case CURLOPT_CONNECT_TO:
			case CURLOPT_MIMEPOST:

				//todo
				break;

			//case CURLOPT_READDATA:
			//case CURLOPT_WRITEDATA:
			//case CURLOPT_HEADERDATA:
			//case CURLOPT_PROGRESSDATA:

			case CURLOPT_READFUNCTION:
			{
				curl_gc_mutex.Lock ();
				if(data->readCallback) {
					delete data->readCallback;
				}
				data->readCallback = new ValuePointer(parameter);
				code = curl_easy_setopt (data->curl, type, read_callback);
				curl_easy_setopt (data->curl, CURLOPT_READDATA, data);
				curl_gc_mutex.Unlock ();
				break;
			}
			case CURLOPT_SEEKFUNCTION:
			{
				curl_gc_mutex.Lock ();

				if(data->seekCallback) {
					delete data->seekCallback;
				}
				data->seekCallback = new ValuePointer(parameter);
				// seek function is needed to support redirects
				curl_easy_setopt (data->curl, CURLOPT_SEEKFUNCTION, seek_callback);
				curl_easy_setopt (data->curl, CURLOPT_SEEKDATA, data);

				curl_gc_mutex.Unlock ();
				break;
			}
			case CURLOPT_WRITEFUNCTION:
			{
				curl_gc_mutex.Lock ();
				if(data->writeCallback) {
					delete data->seekCallback;
				}
				data->writeCallback = new ValuePointer(parameter);
				code = curl_easy_setopt (data->curl, type, write_callback);
				curl_easy_setopt (data->curl, CURLOPT_WRITEDATA, data);

				curl_gc_mutex.Unlock ();
				break;
			}
			case CURLOPT_HEADERFUNCTION:
			{
				curl_gc_mutex.Lock ();
				if(data->headerCallback) {
					delete data->seekCallback;
				}
				data->headerCallback = new ValuePointer(parameter);
				code = curl_easy_setopt (data->curl, type, header_callback);
				curl_easy_setopt (data->curl, CURLOPT_HEADERDATA, data);

				curl_gc_mutex.Unlock ();
				break;
			}
			case CURLOPT_PROGRESSFUNCTION:
			{
				curl_gc_mutex.Lock ();
				if(data->progressCallback) {
					delete data->seekCallback;
				}
				data->progressCallback = new ValuePointer(parameter);
				code = curl_easy_setopt (data->curl, type, progress_callback);
				curl_easy_setopt (data->curl, CURLOPT_PROGRESSDATA, data);
				curl_easy_setopt (data->curl, CURLOPT_NOPROGRESS, false);

				curl_gc_mutex.Unlock ();
				break;
			}
			case CURLOPT_XFERINFOFUNCTION:
			{
				curl_gc_mutex.Lock ();
				if(data->xferInfoCallback) {
					delete data->seekCallback;
				}
				data->xferInfoCallback = new ValuePointer(parameter);
				code = curl_easy_setopt (data->curl, type, xferinfo_callback);
				curl_easy_setopt (data->curl, CURLOPT_XFERINFODATA, data);
				curl_easy_setopt (data->curl, CURLOPT_NOPROGRESS, false);

				curl_gc_mutex.Unlock ();
				break;
			}

			case CURLOPT_HTTPHEADER:
			{
				curl_gc_mutex.Lock ();

				if(data->slist) {
					curl_slist_free_all(data->slist);
					data->slist = nullptr;
				}

				struct curl_slist *chunk = NULL;
				int size = val_array_size (parameter);

				for (int i = 0; i < size; i++) {

					chunk = curl_slist_append (chunk, val_string (val_array_i (parameter, i)));

				}

				data->slist = chunk;

				code = curl_easy_setopt (data->curl, type, chunk);
				curl_gc_mutex.Unlock ();
				break;
			}

			default:

				break;

		}

		return code;

	}


	HL_PRIM int HL_NAME(hl_curl_easy_setopt) (HL_CFFIPointer* handle, int option, vdynamic* parameter, Bytes* bytes) {

		CURLcode code = CURLE_OK;
		CURLData *data = CURLData::fromCFFI(handle);
		CURL* easy_handle = data->curl;
		CURLoption type = (CURLoption)option;

		switch (type) {

			case CURLOPT_VERBOSE:
			case CURLOPT_HEADER:
			case CURLOPT_NOPROGRESS:
			case CURLOPT_NOSIGNAL:
			case CURLOPT_WILDCARDMATCH:
			case CURLOPT_FAILONERROR:
			case CURLOPT_DNS_USE_GLOBAL_CACHE:
			case CURLOPT_TCP_NODELAY:
			case CURLOPT_TCP_KEEPALIVE:
			case CURLOPT_SASL_IR:
			case CURLOPT_AUTOREFERER:
			case CURLOPT_TRANSFER_ENCODING:
			case CURLOPT_FOLLOWLOCATION:
			case CURLOPT_UNRESTRICTED_AUTH:
			case CURLOPT_PUT:
			case CURLOPT_POST:
			case CURLOPT_COOKIESESSION:
			case CURLOPT_HTTPGET:
			case CURLOPT_IGNORE_CONTENT_LENGTH:
			case CURLOPT_HTTP_CONTENT_DECODING:
			case CURLOPT_HTTP_TRANSFER_DECODING:
			case CURLOPT_DIRLISTONLY:
			case CURLOPT_APPEND:
			case CURLOPT_FTP_USE_EPRT:
			case CURLOPT_FTP_USE_EPSV:
			case CURLOPT_FTP_USE_PRET:
			case CURLOPT_FTP_CREATE_MISSING_DIRS:
			case CURLOPT_FTP_SKIP_PASV_IP:
			case CURLOPT_TRANSFERTEXT:
			case CURLOPT_CRLF:
			case CURLOPT_NOBODY:
			case CURLOPT_UPLOAD:
			case CURLOPT_FRESH_CONNECT:
			case CURLOPT_FORBID_REUSE:
			case CURLOPT_CONNECT_ONLY:
			case CURLOPT_USE_SSL:
			//case CURLOPT_SSL_ENABLE_ALPN:
			//case CURLOPT_SSL_ENABLE_NPN:
			case CURLOPT_SSL_VERIFYPEER:
			case CURLOPT_SSL_SESSIONID_CACHE:
			case CURLOPT_TCP_FASTOPEN:
			case CURLOPT_KEEP_SENDING_ON_ERROR:
			case CURLOPT_PATH_AS_IS:
			case CURLOPT_SSL_VERIFYSTATUS:
			case CURLOPT_SSL_FALSESTART:
			case CURLOPT_PIPEWAIT:
			case CURLOPT_TFTP_NO_OPTIONS:
			case CURLOPT_SUPPRESS_CONNECT_HEADERS:
			case CURLOPT_SSH_COMPRESSION:

				code = curl_easy_setopt (easy_handle, type, parameter->v.b);
				break;

			case CURLOPT_SSL_VERIFYHOST:
			case CURLOPT_PROTOCOLS:
			case CURLOPT_REDIR_PROTOCOLS:
			case CURLOPT_PROXYPORT:
			case CURLOPT_PROXYTYPE:
			case CURLOPT_HTTPPROXYTUNNEL:
			case CURLOPT_SOCKS5_GSSAPI_NEC:
			case CURLOPT_LOCALPORT:
			case CURLOPT_LOCALPORTRANGE:
			case CURLOPT_DNS_CACHE_TIMEOUT:
			case CURLOPT_BUFFERSIZE:
			case CURLOPT_PORT:
			case CURLOPT_ADDRESS_SCOPE:
			case CURLOPT_TCP_KEEPIDLE:
			case CURLOPT_TCP_KEEPINTVL:
			case CURLOPT_NETRC:
			case CURLOPT_HTTPAUTH:
			case CURLOPT_PROXYAUTH:
			case CURLOPT_MAXREDIRS:
			case CURLOPT_POSTREDIR:
			case CURLOPT_POSTFIELDSIZE:
			//case CURLOPT_HEADEROPT:
			case CURLOPT_HTTP_VERSION:
			//case CURLOPT_EXPECT_100_TIMEOUT_MS:
			case CURLOPT_TFTP_BLKSIZE:
			case CURLOPT_FTP_RESPONSE_TIMEOUT:
			case CURLOPT_FTPSSLAUTH:
			case CURLOPT_FTP_SSL_CCC:
			case CURLOPT_FTP_FILEMETHOD:
			case CURLOPT_RTSP_REQUEST:
			case CURLOPT_RTSP_CLIENT_CSEQ:
			case CURLOPT_RTSP_SERVER_CSEQ:
			case CURLOPT_PROXY_TRANSFER_MODE:
			case CURLOPT_RESUME_FROM:
			case CURLOPT_FILETIME:
			case CURLOPT_INFILESIZE:
			case CURLOPT_MAXFILESIZE:
			case CURLOPT_TIMECONDITION:
			case CURLOPT_TIMEVALUE:
			case CURLOPT_TIMEOUT:
			case CURLOPT_TIMEOUT_MS:
			case CURLOPT_LOW_SPEED_LIMIT:
			case CURLOPT_LOW_SPEED_TIME:
			case CURLOPT_MAXCONNECTS:
			case CURLOPT_CONNECTTIMEOUT:
			case CURLOPT_CONNECTTIMEOUT_MS:
			case CURLOPT_IPRESOLVE:
			case CURLOPT_ACCEPTTIMEOUT_MS:
			case CURLOPT_SSLENGINE_DEFAULT:
			case CURLOPT_SSLVERSION:
			case CURLOPT_CERTINFO:
			case CURLOPT_SSL_OPTIONS:
			case CURLOPT_GSSAPI_DELEGATION:
			case CURLOPT_SSH_AUTH_TYPES:
			case CURLOPT_NEW_FILE_PERMS:
			case CURLOPT_NEW_DIRECTORY_PERMS:
			case CURLOPT_STREAM_WEIGHT:
			case CURLOPT_PROXY_SSL_VERIFYPEER:
			case CURLOPT_PROXY_SSL_VERIFYHOST:
			case CURLOPT_PROXY_SSLVERSION:
			case CURLOPT_PROXY_SSL_OPTIONS:
			case CURLOPT_SOCKS5_AUTH:

				code = curl_easy_setopt (easy_handle, type, parameter->v.i);
				break;

			case CURLOPT_POSTFIELDSIZE_LARGE:
			case CURLOPT_RESUME_FROM_LARGE:
			case CURLOPT_INFILESIZE_LARGE:
			case CURLOPT_MAXFILESIZE_LARGE:
			case CURLOPT_MAX_SEND_SPEED_LARGE:
			case CURLOPT_MAX_RECV_SPEED_LARGE:

				code = curl_easy_setopt (easy_handle, type, parameter->v.f);
				break;

			case CURLOPT_ERRORBUFFER:
			case CURLOPT_URL:
			case CURLOPT_PROXY:
			case CURLOPT_NOPROXY:
			case CURLOPT_SOCKS5_GSSAPI_SERVICE:
			case CURLOPT_INTERFACE:
			case CURLOPT_NETRC_FILE:
			case CURLOPT_USERPWD:
			case CURLOPT_PROXYUSERPWD:
			case CURLOPT_USERNAME:
			case CURLOPT_PASSWORD:
			case CURLOPT_LOGIN_OPTIONS:
			case CURLOPT_PROXYUSERNAME:
			case CURLOPT_PROXYPASSWORD:
			case CURLOPT_TLSAUTH_USERNAME:
			case CURLOPT_TLSAUTH_PASSWORD:
			case CURLOPT_XOAUTH2_BEARER:
			case CURLOPT_ACCEPT_ENCODING:
			case CURLOPT_POSTFIELDS:
			case CURLOPT_COPYPOSTFIELDS:
			case CURLOPT_REFERER:
			case CURLOPT_USERAGENT:
			case CURLOPT_COOKIE:
			case CURLOPT_COOKIEFILE:
			case CURLOPT_COOKIEJAR:
			case CURLOPT_COOKIELIST:
			case CURLOPT_MAIL_FROM:
			case CURLOPT_MAIL_AUTH:
			case CURLOPT_FTPPORT:
			case CURLOPT_FTP_ALTERNATIVE_TO_USER:
			case CURLOPT_FTP_ACCOUNT:
			case CURLOPT_RTSP_SESSION_ID:
			case CURLOPT_RTSP_STREAM_URI:
			case CURLOPT_RTSP_TRANSPORT:
			case CURLOPT_RANGE:
			case CURLOPT_CUSTOMREQUEST:
			case CURLOPT_DNS_INTERFACE:
			case CURLOPT_DNS_LOCAL_IP4:
			case CURLOPT_DNS_LOCAL_IP6:
			case CURLOPT_SSLCERT:
			case CURLOPT_SSLCERTTYPE:
			case CURLOPT_SSLKEY:
			case CURLOPT_SSLKEYTYPE:
			case CURLOPT_KEYPASSWD:
			case CURLOPT_SSLENGINE:
			case CURLOPT_CAINFO:
			case CURLOPT_ISSUERCERT:
			case CURLOPT_CAPATH:
			case CURLOPT_CRLFILE:
			case CURLOPT_RANDOM_FILE:
			case CURLOPT_EGDSOCKET:
			case CURLOPT_SSL_CIPHER_LIST:
			case CURLOPT_KRBLEVEL:
			case CURLOPT_SSH_HOST_PUBLIC_KEY_MD5:
			case CURLOPT_SSH_PUBLIC_KEYFILE:
			case CURLOPT_SSH_PRIVATE_KEYFILE:
			case CURLOPT_SSH_KNOWNHOSTS:
			case CURLOPT_PINNEDPUBLICKEY:
			case CURLOPT_UNIX_SOCKET_PATH:
			case CURLOPT_PROXY_SERVICE_NAME:
			case CURLOPT_SERVICE_NAME:
			case CURLOPT_DEFAULT_PROTOCOL:
			case CURLOPT_PROXY_CAINFO:
			case CURLOPT_PROXY_CAPATH:
			case CURLOPT_PROXY_TLSAUTH_USERNAME:
			case CURLOPT_PROXY_TLSAUTH_PASSWORD:
			case CURLOPT_PROXY_TLSAUTH_TYPE:
			case CURLOPT_PROXY_SSLCERT:
			case CURLOPT_PROXY_SSLCERTTYPE:
			case CURLOPT_PROXY_SSLKEY:
			case CURLOPT_PROXY_SSLKEYTYPE:
			case CURLOPT_PROXY_KEYPASSWD:
			case CURLOPT_PROXY_SSL_CIPHER_LIST:
			case CURLOPT_PROXY_CRLFILE:
			case CURLOPT_PRE_PROXY:
			case CURLOPT_PROXY_PINNEDPUBLICKEY:
			case CURLOPT_ABSTRACT_UNIX_SOCKET:
			case CURLOPT_REQUEST_TARGET:
			{
				hl_vstring* str = (hl_vstring*)parameter;
				code = curl_easy_setopt (easy_handle, type, str ? hl_to_utf8 (str->bytes) : NULL);
				break;
			}

			case CURLOPT_IOCTLFUNCTION:
			case CURLOPT_IOCTLDATA:
			case CURLOPT_SEEKFUNCTION:
			case CURLOPT_SEEKDATA:
			case CURLOPT_SOCKOPTFUNCTION:
			case CURLOPT_SOCKOPTDATA:
			case CURLOPT_OPENSOCKETFUNCTION:
			case CURLOPT_OPENSOCKETDATA:
			case CURLOPT_CLOSESOCKETFUNCTION:
			case CURLOPT_CLOSESOCKETDATA:
			case CURLOPT_DEBUGFUNCTION:
			case CURLOPT_DEBUGDATA:
			case CURLOPT_SSL_CTX_FUNCTION:
			case CURLOPT_SSL_CTX_DATA:
			case CURLOPT_CONV_TO_NETWORK_FUNCTION:
			case CURLOPT_CONV_FROM_NETWORK_FUNCTION:
			case CURLOPT_CONV_FROM_UTF8_FUNCTION:
			case CURLOPT_INTERLEAVEFUNCTION:
			case CURLOPT_INTERLEAVEDATA:
			case CURLOPT_CHUNK_BGN_FUNCTION:
			case CURLOPT_CHUNK_END_FUNCTION:
			case CURLOPT_CHUNK_DATA:
			case CURLOPT_FNMATCH_FUNCTION:
			case CURLOPT_FNMATCH_DATA:
			case CURLOPT_STDERR:
			case CURLOPT_HTTPPOST:
			//case CURLOPT_PROXYHEADER:
			case CURLOPT_HTTP200ALIASES:
			case CURLOPT_MAIL_RCPT:
			case CURLOPT_QUOTE:
			case CURLOPT_POSTQUOTE:
			case CURLOPT_PREQUOTE:
			case CURLOPT_RESOLVE:
			case CURLOPT_SSH_KEYFUNCTION:
			case CURLOPT_SSH_KEYDATA:
			case CURLOPT_PRIVATE:
			case CURLOPT_SHARE:
			case CURLOPT_TELNETOPTIONS:
			case CURLOPT_STREAM_DEPENDS:
			case CURLOPT_STREAM_DEPENDS_E:
			case CURLOPT_CONNECT_TO:
			case CURLOPT_MIMEPOST:

				//todo
				break;

			//case CURLOPT_READDATA:
			//case CURLOPT_WRITEDATA:
			//case CURLOPT_HEADERDATA:
			//case CURLOPT_PROGRESSDATA:

			case CURLOPT_READFUNCTION:
			{
				// curl_gc_mutex.Lock ();
				// ValuePointer* callback = new ValuePointer (parameter);
				// readCallbacks[handle] = callback;
				// code = curl_easy_setopt (easy_handle, type, read_callback);
				// curl_easy_setopt (easy_handle, CURLOPT_READDATA, handle);
				// curl_gc_mutex.Unlock ();
				break;
			}
			case CURLOPT_READDATA:
			{
				// curl_gc_mutex.Lock ();

				// curl_easy_setopt (easy_handle, CURLOPT_SEEKFUNCTION, seek_callback);
				// curl_easy_setopt (easy_handle, CURLOPT_SEEKDATA, data);
				// code = curl_easy_setopt (easy_handle, CURLOPT_READFUNCTION, read_callback);
				// curl_easy_setopt (easy_handle, CURLOPT_READDATA, data);

				// curl_gc_mutex.Unlock ();
				break;
			}
			case CURLOPT_WRITEFUNCTION:
			{
				curl_gc_mutex.Lock ();
				if(data->writeCallback) {
					delete data->writeCallback;
				}
				data->writeCallback = new ValuePointer(parameter);
				code = curl_easy_setopt (easy_handle, type, write_callback);
				curl_easy_setopt (easy_handle, CURLOPT_WRITEDATA, data);

				curl_gc_mutex.Unlock ();
				break;
			}
			case CURLOPT_HEADERFUNCTION:
			{
				curl_gc_mutex.Lock ();
				if(data->headerCallback) {
					delete data->headerCallback;
				}
				data->headerCallback = new ValuePointer(parameter);
				code = curl_easy_setopt (easy_handle, type, header_callback);
				curl_easy_setopt (easy_handle, CURLOPT_HEADERDATA, data);

				curl_gc_mutex.Unlock ();
				break;
			}
			case CURLOPT_PROGRESSFUNCTION:
			{
				curl_gc_mutex.Lock ();
				if(data->progressCallback) {
					delete data->progressCallback;
				}
				data->progressCallback = new ValuePointer(parameter);
				code = curl_easy_setopt (easy_handle, type, progress_callback);
				curl_easy_setopt (easy_handle, CURLOPT_PROGRESSDATA, data);
				curl_easy_setopt (easy_handle, CURLOPT_NOPROGRESS, false);

				curl_gc_mutex.Unlock ();
				break;
			}
			case CURLOPT_XFERINFOFUNCTION:
			{
				curl_gc_mutex.Lock ();
				if(data->xferInfoCallback) {
					delete data->xferInfoCallback;
				}
				data->xferInfoCallback = new ValuePointer(parameter);
				code = curl_easy_setopt (easy_handle, type, xferinfo_callback);
				curl_easy_setopt (easy_handle, CURLOPT_XFERINFODATA, data);
				curl_easy_setopt (easy_handle, CURLOPT_NOPROGRESS, false);

				curl_gc_mutex.Unlock ();
				break;
			}

			case CURLOPT_HTTPHEADER:
			{
				curl_gc_mutex.Lock ();

				if (data->slist) {

					curl_slist_free_all (data->slist);
					data->slist = nullptr;
				}

				struct curl_slist *chunk = NULL;
				varray* stringList = (varray*)parameter;
				hl_vstring** stringListData = hl_aptr (stringList, hl_vstring*);
				int size = stringList->size;
				hl_vstring* sdata;

				for (int i = 0; i < size; i++) {

					sdata = *stringListData++;
					chunk = curl_slist_append (chunk, sdata ? hl_to_utf8 (sdata->bytes) : NULL);

				}

				data->slist = chunk;

				code = curl_easy_setopt (easy_handle, type, chunk);
				curl_gc_mutex.Unlock ();
				break;
			}

			default:

				break;

		}

		return code;

	}


	value lime_curl_easy_strerror (int errornum) {

		const char* result = curl_easy_strerror ((CURLcode)errornum);
		return result ? alloc_string (result) : alloc_null ();

	}


	HL_PRIM vbyte* HL_NAME(hl_curl_easy_strerror) (int errornum) {

		const char* result = curl_easy_strerror ((CURLcode)errornum);
		int length = strlen (result);
		char* _result = (char*)malloc (length + 1);
		strcpy (_result, result);
		return (vbyte*)_result;

	}


	value lime_curl_easy_unescape (value curl, HxString url, int inlength, int outlength) {

		char* result = curl_easy_unescape (CURLData::fromCFFI(curl)->curl, url.__s, inlength, &outlength);
		return result ? alloc_string (result) : alloc_null ();

	}


	HL_PRIM vbyte* HL_NAME(hl_curl_easy_unescape) (HL_CFFIPointer* curl, hl_vstring* url, int inlength, int outlength) {

		char* result = curl_easy_unescape (CURLData::fromCFFI(curl)->curl, url ? hl_to_utf8 (url->bytes) : NULL, inlength, &outlength);
		int length = strlen (result);
		char* _result = (char*)malloc (length + 1);
		strcpy (_result, result);
		return (vbyte*)_result;

	}


	//lime_curl_formadd;
	//lime_curl_formfree;
	//lime_curl_formget;


	double lime_curl_getdate (HxString datestring, double now) {

		time_t time = (time_t)now;
		return curl_getdate (datestring.__s, &time);

	}


	HL_PRIM double HL_NAME(hl_curl_getdate) (hl_vstring* datestring, double now) {

		time_t time = (time_t)now;
		return curl_getdate (datestring ? hl_to_utf8 (datestring->bytes) : NULL, &time);

	}


	void lime_curl_global_cleanup () {

		curl_global_cleanup ();

	}


	HL_PRIM void HL_NAME(hl_curl_global_cleanup) () {

		curl_global_cleanup ();

	}


	int lime_curl_global_init (int flags) {

		return curl_global_init (flags);

	}


	HL_PRIM int HL_NAME(hl_curl_global_init) (int flags) {

		return curl_global_init (flags);

	}


	int lime_curl_multi_cleanup (value multi_handle) {

		// curl_gc_mutex.Lock ();

		// CURLMcode result = curl_multi_cleanup ((CURLM*)val_data (multi_handle));
		delete CURLMultiData::fromCFFI(multi_handle);

		// curl_gc_mutex.Unlock ();

		return CURLM_OK;

	}


	HL_PRIM int HL_NAME(hl_curl_multi_cleanup) (HL_CFFIPointer* multi_handle) {

		// curl_gc_mutex.Lock ();

		// CURLMcode result = curl_multi_cleanup ((CURLM*)val_data (multi_handle));
		delete CURLMultiData::fromCFFI(multi_handle);

		// curl_gc_mutex.Unlock ();

		return CURLM_OK;

	}


	value lime_curl_multi_init () {
		return (new CURLMultiData())->allocCFFI();
	}


	HL_PRIM HL_CFFIPointer* HL_NAME(hl_curl_multi_init) () {
		return (new CURLMultiData())->allocCFFI_HL();
	}


	int lime_curl_multi_add_handle (value multi_handle, value curl_object, value curl_handle) {

		return CURLMultiData::fromCFFI(multi_handle)->AddHandle(CURLData::fromCFFI(curl_handle));

	}


	HL_PRIM int HL_NAME(hl_curl_multi_add_handle) (HL_CFFIPointer* multi_handle, vdynamic* curl_object, HL_CFFIPointer* curl_handle) {

		return CURLMultiData::fromCFFI(multi_handle)->AddHandle(CURLData::fromCFFI(curl_handle));

	}


	int lime_curl_multi_get_running_handles (value multi_handle) {

		return CURLMultiData::fromCFFI(multi_handle)->runningHandles;

	}


	HL_PRIM int HL_NAME(hl_curl_multi_get_running_handles) (HL_CFFIPointer* multi_handle) {

		return CURLMultiData::fromCFFI(multi_handle)->runningHandles;

	}


	value lime_curl_multi_info_read (value multi_handle) {

		CURLMultiData *mdata = CURLMultiData::fromCFFI(multi_handle);
		int msgs_in_queue;
		CURLMsg* msg = curl_multi_info_read (mdata->curlm, &msgs_in_queue);

		if (msg) {

			//const field val_id ("msg");
			const field id_curl = val_id ("curl");
			const field id_result = val_id ("result");

			CURL* curl = msg->easy_handle;
			value result = alloc_empty_object ();

			if (mdata->handles.find (curl) != mdata->handles.end ()) {

				value obj = (value)mdata->handles[curl]->haxe_object->Get();
				alloc_field (result, id_curl, obj);

			} else {

				// TODO?
				alloc_field (result, id_curl, alloc_null ());

			}

			alloc_field (result, id_result, alloc_int (msg->data.result));
			return result;

		} else {

			return alloc_null ();

		}

	}


	HL_PRIM vdynamic* HL_NAME(hl_curl_multi_info_read) (HL_CFFIPointer* multi_handle, vdynamic* result) {
		CURLMultiData *mdata = CURLMultiData::fromCFFI(multi_handle);
		int msgs_in_queue;
		CURLMsg* msg = curl_multi_info_read (mdata->curlm, &msgs_in_queue);

		if (msg) {

			//const field val_id ("msg");
			const int id_curl = hl_hash_utf8 ("curl");
			const int id_result = hl_hash_utf8 ("result");

			CURL* curl = msg->easy_handle;

			if (mdata->handles.find (curl) != mdata->handles.end ()) {

				vdynamic* obj = (vdynamic*)mdata->handles[curl]->haxe_object->Get();
				hl_dyn_setp (result, id_curl, &hlt_dyn, obj);

			} else {

				// TODO?
				hl_dyn_setp (result, id_curl, &hlt_dyn, NULL);

			}

			hl_dyn_seti (result, id_result, &hlt_i32, msg->data.result);
			return result;

		} else {

			return NULL;

		}

	}


	int lime_curl_multi_perform (value multi_handle) {
		// System::GCEnterBlocking();
		auto code = CURLMultiData::fromCFFI(multi_handle)->Perform();
		// System::GCExitBlocking();
		return code;
	}


	HL_PRIM int HL_NAME(hl_curl_multi_perform) (HL_CFFIPointer* multi_handle) {
		// hl_blocking(true);
		auto code = CURLMultiData::fromCFFI(multi_handle)->Perform();
		// hl_blocking(false);
		return code;
	}


	int lime_curl_multi_remove_handle (value multi_handle, value curl_handle) {

                return CURLMultiData::fromCFFI(multi_handle)
                    ->RemoveHandle(CURLData::fromCFFI(curl_handle));
        }


	HL_PRIM int HL_NAME(hl_curl_multi_remove_handle) (HL_CFFIPointer* multi_handle, HL_CFFIPointer* curl_handle) {

                return CURLMultiData::fromCFFI(multi_handle)
                    ->RemoveHandle(CURLData::fromCFFI(curl_handle));
        }


	int lime_curl_multi_setopt (value multi_handle, int option, value parameter) {

		CURLMultiData *data = CURLMultiData::fromCFFI(multi_handle);
		CURLMcode code = CURLM_OK;
		CURLM* multi = data->curlm;
		CURLMoption type = (CURLMoption)option;

		switch (type) {

			case CURLMOPT_PIPELINING:

				code = curl_multi_setopt (multi, type, val_bool (parameter));
				break;

			case CURLMOPT_MAXCONNECTS:
			case CURLMOPT_MAX_HOST_CONNECTIONS:
			case CURLMOPT_MAX_PIPELINE_LENGTH:
			case CURLMOPT_MAX_TOTAL_CONNECTIONS:
			case CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE:
			case CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE:

				code = curl_multi_setopt (multi, type, val_int (parameter));
				break;

			case CURLMOPT_SOCKETFUNCTION:
			case CURLMOPT_SOCKETDATA:
			case CURLMOPT_TIMERFUNCTION:
			case CURLMOPT_TIMERDATA:
			case CURLMOPT_PUSHFUNCTION:
			case CURLMOPT_PUSHDATA:

				// TODO?
				break;

			case CURLMOPT_PIPELINING_SITE_BL:
			case CURLMOPT_PIPELINING_SERVER_BL:

				// TODO, array to slist
				break;

			default:

				break;

		}

		return code;

	}


	HL_PRIM int HL_NAME(hl_curl_multi_setopt) (HL_CFFIPointer* multi_handle, int option, vdynamic* parameter) {

		CURLMultiData *data = CURLMultiData::fromCFFI(multi_handle);
		CURLMcode code = CURLM_OK;
		CURLM* multi = data->curlm;
		CURLMoption type = (CURLMoption)option;

		switch (type) {

			case CURLMOPT_PIPELINING:

				code = curl_multi_setopt (multi, type, parameter->v.b);
				break;

			case CURLMOPT_MAXCONNECTS:
			case CURLMOPT_MAX_HOST_CONNECTIONS:
			case CURLMOPT_MAX_PIPELINE_LENGTH:
			case CURLMOPT_MAX_TOTAL_CONNECTIONS:
			case CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE:
			case CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE:

				code = curl_multi_setopt (multi, type, parameter->v.i);
				break;

			case CURLMOPT_SOCKETFUNCTION:
			case CURLMOPT_SOCKETDATA:
			case CURLMOPT_TIMERFUNCTION:
			case CURLMOPT_TIMERDATA:
			case CURLMOPT_PUSHFUNCTION:
			case CURLMOPT_PUSHDATA:

				// TODO?
				break;

			case CURLMOPT_PIPELINING_SITE_BL:
			case CURLMOPT_PIPELINING_SERVER_BL:

				// TODO, array to slist
				break;

			default:

				break;

		}

		return code;

	}


	int lime_curl_multi_wait (value multi_handle, int timeout_ms) {

		System::GCEnterBlocking ();

		int retcode;
		CURLMcode result = curl_multi_wait (CURLMultiData::fromCFFI(multi_handle)->curlm, 0, 0, timeout_ms, &retcode);

		System::GCExitBlocking ();
		return result;

	}


	HL_PRIM int HL_NAME(hl_curl_multi_wait) (HL_CFFIPointer* multi_handle, int timeout_ms) {

		System::GCEnterBlocking ();

		int retcode;
		CURLMcode result = curl_multi_wait (CURLMultiData::fromCFFI(multi_handle)->curlm, 0, 0, timeout_ms, &retcode);

		System::GCExitBlocking ();
		return result;

	}


	//lime_curl_multi_add_handle
	//lime_curl_multi_assign
	//lime_curl_multi_cleanup
	//lime_curl_multi_fdset
	//lime_curl_multi_info_read
	//lime_curl_multi_init
	//lime_curl_multi_perform
	//lime_curl_multi_remove_handle
	//lime_curl_multi_setopt
	//lime_curl_multi_socket
	//lime_curl_multi_socket_action
	//lime_curl_multi_strerror
	//lime_curl_multi_timeout

	//lime_curl_share_cleanup
	//lime_curl_share_init
	//lime_curl_share_setopt
	//lime_curl_share_strerror

	//lime_curl_slist_append
	//lime_curl_slist_free_all


	value lime_curl_version () {

		char* result = curl_version ();
		return result ? alloc_string (result) : alloc_null ();

	}


	HL_PRIM vbyte* HL_NAME(hl_curl_version) () {

		char* result = curl_version ();
		int length = strlen (result);
		char* _result = (char*)malloc (length + 1);
		strcpy (_result, result);
		return (vbyte*)_result;

	}


	value lime_curl_version_info (int type) {

		curl_version_info_data* data = curl_version_info ((CURLversion)type);

		// TODO

		return alloc_null ();

	}


	HL_PRIM vdynamic* HL_NAME(hl_curl_version_info) (int type) {

		curl_version_info_data* data = curl_version_info ((CURLversion)type);

		// TODO

		return NULL;

	}


	DEFINE_PRIME1v (lime_curl_easy_cleanup);
	DEFINE_PRIME2v (lime_curl_easy_duphandle);
	DEFINE_PRIME3 (lime_curl_easy_escape);
	DEFINE_PRIME2 (lime_curl_easy_getinfo);
	DEFINE_PRIME1v (lime_curl_easy_init);
	DEFINE_PRIME1v (lime_curl_easy_flush);
	DEFINE_PRIME2 (lime_curl_easy_pause);
	DEFINE_PRIME1 (lime_curl_easy_perform);
	DEFINE_PRIME4 (lime_curl_easy_recv);
	DEFINE_PRIME1v (lime_curl_easy_reset);
	DEFINE_PRIME4 (lime_curl_easy_send);
	DEFINE_PRIME4 (lime_curl_easy_setopt);
	DEFINE_PRIME1 (lime_curl_easy_strerror);
	DEFINE_PRIME4 (lime_curl_easy_unescape);
	DEFINE_PRIME2 (lime_curl_getdate);
	DEFINE_PRIME0v (lime_curl_global_cleanup);
	DEFINE_PRIME1 (lime_curl_global_init);
	DEFINE_PRIME1 (lime_curl_multi_cleanup);
	DEFINE_PRIME0 (lime_curl_multi_init);
	DEFINE_PRIME3 (lime_curl_multi_add_handle);
	DEFINE_PRIME1 (lime_curl_multi_get_running_handles);
	DEFINE_PRIME1 (lime_curl_multi_info_read);
	DEFINE_PRIME1 (lime_curl_multi_perform);
	DEFINE_PRIME2 (lime_curl_multi_remove_handle);
	DEFINE_PRIME3 (lime_curl_multi_setopt);
	DEFINE_PRIME2 (lime_curl_multi_wait);
	DEFINE_PRIME0 (lime_curl_version);
	DEFINE_PRIME1 (lime_curl_version_info);


	#define _TBYTES _OBJ (_I32 _BYTES)
	#define _TCFFIPOINTER _DYN

	DEFINE_HL_PRIM (_VOID, hl_curl_easy_cleanup, _TCFFIPOINTER);
	DEFINE_HL_PRIM (_TCFFIPOINTER, hl_curl_easy_duphandle, _TCFFIPOINTER _DYN);
	DEFINE_HL_PRIM (_BYTES, hl_curl_easy_escape, _TCFFIPOINTER _STRING _I32);
	DEFINE_HL_PRIM (_DYN, hl_curl_easy_getinfo, _TCFFIPOINTER _I32);
	DEFINE_HL_PRIM (_TCFFIPOINTER, hl_curl_easy_init, _DYN);
	DEFINE_HL_PRIM (_VOID, hl_curl_easy_flush, _TCFFIPOINTER);
	DEFINE_HL_PRIM (_I32, hl_curl_easy_pause, _TCFFIPOINTER _I32);
	DEFINE_HL_PRIM (_I32, hl_curl_easy_perform, _TCFFIPOINTER);
	DEFINE_HL_PRIM (_I32, hl_curl_easy_recv, _TCFFIPOINTER _F64 _I32 _I32);
	DEFINE_HL_PRIM (_VOID, hl_curl_easy_reset, _TCFFIPOINTER);
	DEFINE_HL_PRIM (_I32, hl_curl_easy_send, _TCFFIPOINTER _F64 _I32 _I32);
	DEFINE_HL_PRIM (_I32, hl_curl_easy_setopt, _TCFFIPOINTER _I32 _DYN _TBYTES);
	DEFINE_HL_PRIM (_BYTES, hl_curl_easy_strerror, _I32);
	DEFINE_HL_PRIM (_BYTES, hl_curl_easy_unescape, _TCFFIPOINTER _STRING _I32 _I32);
	DEFINE_HL_PRIM (_F64, hl_curl_getdate, _STRING _F64);
	DEFINE_HL_PRIM (_VOID, hl_curl_global_cleanup, _NO_ARG);
	DEFINE_HL_PRIM (_I32, hl_curl_global_init, _I32);
	DEFINE_HL_PRIM (_I32, hl_curl_multi_cleanup, _TCFFIPOINTER);
	DEFINE_HL_PRIM (_TCFFIPOINTER, hl_curl_multi_init, _NO_ARG);
	DEFINE_HL_PRIM (_I32, hl_curl_multi_add_handle, _TCFFIPOINTER _DYN _TCFFIPOINTER);
	DEFINE_HL_PRIM (_I32, hl_curl_multi_get_running_handles, _TCFFIPOINTER);
	DEFINE_HL_PRIM (_DYN, hl_curl_multi_info_read, _TCFFIPOINTER _DYN);
	DEFINE_HL_PRIM (_I32, hl_curl_multi_perform, _TCFFIPOINTER);
	DEFINE_HL_PRIM (_I32, hl_curl_multi_remove_handle, _TCFFIPOINTER _TCFFIPOINTER);
	DEFINE_HL_PRIM (_I32, hl_curl_multi_setopt, _TCFFIPOINTER _I32 _DYN);
	DEFINE_HL_PRIM (_I32, hl_curl_multi_wait, _TCFFIPOINTER _I32);
	DEFINE_HL_PRIM (_BYTES, hl_curl_version, _NO_ARG);
	DEFINE_HL_PRIM (_DYN, hl_curl_version_info, _I32);


}


extern "C" int lime_curl_register_prims () {

	return 0;

}