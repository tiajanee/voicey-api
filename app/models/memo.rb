class Memo < ApplicationRecord
	belongs_to :user
  	validates :title, :date, :text_body, presence: true
end
