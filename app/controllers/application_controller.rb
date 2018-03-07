class ApplicationController < ActionController::API
	include ActionController::HttpAuthentication::Token::ControllerMethods
	before_action :require_login

def require_login
  authorize_request || render_unauthorized("Access denied")
end

# 4. Helper method to find the current_user in a request
def current_user
  @current_user ||= authorize_request
end

# 5. Renders an message when a user is unauthorized
def render_unauthorized(message)
  errors = { errors: [ { detail: message } ] }
  render json: errors, status: :unauthorized
end

private
# 6. Authenticate a user with by token
def authorize_request
  authenticate_with_http_token do |token, options|
    User.find_by(token: token)
  end
end
end
