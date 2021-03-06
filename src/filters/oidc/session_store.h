#ifndef AUTHSERVICE_SESSION_STORE_H
#define AUTHSERVICE_SESSION_STORE_H

#include "src/filters/oidc/token_response.h"

namespace authservice {
namespace filters {
namespace oidc {

class SessionStore;

typedef std::shared_ptr<SessionStore> SessionStorePtr;

class SessionStore {
public:

  virtual void SetTokenResponse(absl::string_view session_id, std::shared_ptr<TokenResponse> token_response) = 0;

  virtual void SetRequestedURL(absl::string_view session_id, absl::string_view requested_url) = 0;

  virtual void ClearRequestedURL(absl::string_view session_id) = 0;

  virtual std::shared_ptr<TokenResponse> GetTokenResponse(absl::string_view session_id) = 0;

  virtual absl::optional<std::string> GetRequestedURL(absl::string_view session_id) = 0;

  virtual void RemoveSession(absl::string_view session_id) = 0;

  virtual void RemoveAllExpired() = 0;
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif //AUTHSERVICE_SESSION_STORE_H
