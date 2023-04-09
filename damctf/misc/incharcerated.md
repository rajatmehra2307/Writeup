### Problem statement ###
In this challenge we are given a simple ruby file, ```jail.rb``` and we need to jailbreak in order to get the flag. The code is
```
#!/usr/bin/env ruby
# RUBY_VERSION == 3.2

puts <<~'HEADER'
      ----------------------------
        ||     ||      ||     ||
        ||     ||      ||     ||
        ||  ___|| ____ ||___  ||
        || /   ||'    `||   \ ||
        ||____/||______||\____||
        ||\   \||      ||/   /||
        || `\  ||      ||  /' ||
        ||    `||\    /||'    ||
        ||     ||\ \/ /||     ||
        ||     || `\/' ||     ||
      ----------------------------
  jailed for crimes against parentheses

HEADER

printf '>>> '
STDOUT.flush
input = readline.chomp

# cant make this too easy
class Object
  def system(*)
    'nice try youre not getting the flag this way'
  end

  def spawn(*)
    'or this way either'
  end
end

if input =~ /[^a-z.;=_ ]/
  # be nice and print out what character failed
  puts "failure builds character: #{Regexp.last_match}"
  exit 1
end

eval(input)
```

### Exploit ###
So we can execute any input we give, but there is character blacklisting in place for the input.
After going through the exploit here - https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-baby-ruby-escaping/ one idea is to execute ```ARGV << "flag"; print while gets;```, but due to the character blacklisting this cannot be done. So in order to bypass this we can execute, ``` input=readline.chomp; eval input``` and in the next prompt enter the above command to get the flag.