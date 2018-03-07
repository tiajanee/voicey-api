require 'rails_helper'

RSpec.describe "UserControllers", type: :request do
  describe "GET /user_controllers" do
    it "works! (now write some real specs)" do
      get user_controllers_path
      expect(response).to have_http_status(200)
    end
  end
end
