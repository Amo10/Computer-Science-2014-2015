#!/usr/bin/perl
while (<>) {
	if (/src=\"([^\"]+)\"/) {
		@a = split(/\//,$1);
		$the_file = @a[$#a];
	
		unless (open($media,$the_file)) {
			print STDERR "Cannot open $the_file: $!\n";
		}
		stat($media);
		if (-e $media) {
			s/src=\"([^\"]+)\"/"src=\"" . $the_file . "\""/seg;
		}
		close($media);
	}

	print $_;
}
