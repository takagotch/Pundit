### Pundit
---

https://github.com/varvet/pundit


```
gem "pundit"
rails g pundit:install

```

```ruby
class ApplicatoinController < ActionController::Base
  include Pundit
  protect_from_forgery
end



```

```
```

