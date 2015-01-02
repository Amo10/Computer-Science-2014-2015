require "rubygems"
require 'RMagick'
include Magick

img = ImageList.new("steg3.png")
i=0
"""img.each_pixel { |pixel, c, r|
  puts pixel.red.to_i
}
puts i

img.each_pixel do |pixel, c, r|
    pixels.push(pixel)
end"""
puts img.export_pixels_to_str(x=0, y=0, columns=img.columns, rows=img.rows, map="RGB", type=CharPixel)