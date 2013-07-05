Passwords
=========

As far as I know, no one has bothered to port the crypt() function to other platforms, or even really looked at it in a long while.

I found myself in need of being able to make unix password hashes in my Go programs, so I went hunting to re-create this functionality. I wasn't able to find the source of crypt() itself (at least not abstracted to the point that I'd have to dig through several libraries of source). But I did find a pure bash recreation of it, at least for sha512. While abhorently slow, this bash script did acurately produce the same output as crypt() (read: same output as mkpasswd). So I used this as a template for recreating it in Go.

Long story short, I did it, and learned that crypt() is absurdly (and unessecarily) complicated (security through obscurity is not security, expecially when the source for your process is very public).

I decided to make this into a library that'll provide the ability to programatically create various proprietary password hashes. So far this is just sha512 from crypt() and MySql's PASSWORD(). If you have/know of others please let me know! (or just make a pull request ;D)