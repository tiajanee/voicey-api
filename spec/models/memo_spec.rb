require 'rails_helper'

# Memo Tests
RSpec.describe Memo, type: :model do
  subject {
    User.new(name: "TJ", email: "thicc@gmail.com")
  }
  describe "Validations" do
    it "is valid with valid attributes" do
      memo = Memo.new(
        title: "My Memo",
        date: DateTime.now.utc,
        text_body: "This is the text body",
        user: subject
      )
      expect(memo).to be_valid
    end
    it "is invalid without a title" do
      bad_memo = Memo.new(
        title: nil,
        date: DateTime.now.utc,
        text_body: "This is the text body",
        user: subject
      )
      expect(bad_memo).to_not be_valid
    end
    it "is invalid without an time" do
      bad_memo = Memo.new(
        title: "My Memo",
        date: nil,
        text_body: "This is the text body",
        user: subject
      )
      expect(bad_memo).to_not be_valid
    end
    it "is invalid without an text body" do
      bad_memo = Memo.new(
        title: "My Memo",
        date: DateTime.now.utc,
        text_body: nil,
        user: subject
      )
      expect(bad_memo).to_not be_valid
    end
    it "is invalid without a user" do
      bad_memo = Memo.new(
        title: "My Memo",
        date: DateTime.now.utc,
        text_body: nil,
        user: nil
      )
      expect(bad_memo).to_not be_valid
    end
  end
  describe "Associations" do
    it "should have many memos" do
      assoc = Memo.reflect_on_association(:user)
      expect(assoc.macro).to eq :belongs_to
    end
  end
end
