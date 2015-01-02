require "rubygems"
require 'RMagick'
include Magick

pixels = [600]
img = ImageList.new("steg3.png")
img.each_pixel do |pixel, c, r|
    pixels.push(pixel)
end
puts pixels