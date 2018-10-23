### Pundit
---

https://github.com/varvet/pundit


```
gem "pundit"
rails g pundit:install

rails g pundit:policy post

```

```ruby
class ApplicatoinController < ActionController::Base
  include Pundit
  protect_from_forgery
end

class PostPolicy
  attr_reader :user, :post
  def initialize(user, post)
    @user = user
    @post = post
  end
  def update?
    user.admin? or not post.published?
  end
end

class PostPolicy < ApplicationPolicy
  def update?
    user.admin? or not record.published?
  end
end

def update
  @post = Post.find(params[:id])
  authorize @post
  if @post.update(post_params)
    redirect_to @post
  else
    render :edit
  end
end

unless PostPolicy.new(current_user, @post).update?
  raise Pundit::NotAuthorizedError, "not allowed to update? this #{@post.inspect}"
end

def publish
  @post = Post.find(params[:id])
  authorize @post, :update?
  @post.publish!
  redirect_to @post
end

def create
  @publication = find_publication
  authorize @publication, policy_class: PublicationPolicy
  @publication.publish!
  redirect_to @publication
end

class PostPolicy < ApplicationPolicy
  def admin_list?
    user.admin?
  end
end

def admin_list
  authorize Post
end

def show
  @user = authorize User.find(params[:id])
end

# app/policies/dashboard_policy.rb
class DashboardPolicy < Struct.new(:user, :dashboard)
end

authorize :dashboard, :show?

class PostPolicy < ApplicationPolicy
  class Scope
    attr_reader :user, :scope
    def initialize(user, scope)
      @user = user
      @scope = scope
    end
    def resolve
      if user.admin?
        scope.all
      else
        scope.where(published: true)
      end
    end
  end
  def update
    user.admin? or not record.published?
  end
end

class PostPolicy < ApplicatoinPolicy
  class Scope < Scope
    if user.admin?
      scope.all
    else
      scope.where(published: true)
    end
  end
  def update?
    user.admin? or not record.published?
  end
end

def index
  @posts = policy_scope(Post)
end
def show
  @post = policy_scope(Post).find(params[:id])
end

def index
  @publications = policy_scope(publication_class, policy_scope_class: PublicationPolicy::Scope)
end

def index
  @post = PostPolicy::Scope.new(current_user, Post).resolve
end

class ApplicationController < ActionController::Base
  include Pundit
  after_action :verify_authorized
end

class ApplicationController < ActionController::Base
  include Pundit
  after_action :verify_authorized, except: :index
  after_action :verify_policy_scoped, only: :index
end

def show
  record = Record.find_by(attribute: "value")
  if record.present?
    authorize record
  else
    skip_authorization
  end
end

class Post
  def self.policy_class
    PostablePolicy
  end
end

class ApplicationPolicy
  def initialize(user, record)
    raise Pundit::NotAuthorizedError, "must be logged in" unless user
    @user = user
    @record = record
  end
  class Scope
    attr_reader :user, :scope
    def initialize(user, scope)
      raise Pundit::NotAuthorizedError, "must be logged in" unless user
      @user = user
      @scope = scope
    end
  end
end

class NilClassPolicy < ApplicationPolicy
  class Scope < Scope
    def resolve
      raise Pundit::NotDefinedError, "Cannot scope Nil Class"
    end
  end
  def show?
    false
  end
end

class ApplicationController < ActionController::Base
  protect_from_forgery
  include Pundit
  rescue_from Pundit::NotAuthorizedError, with: :user_not_authorized
  private
  def user_not_authorized
    flash[:alert] = "You are not authorized to perfrom this action."
    redirect_to(request.referrer || root_path)
  end
end

class ApplicationController < ActionController::Base
  rescue_from Pundit::NotAuthorizedError, with: :user_not_authorized
  private
  def user_not_authorized(exception)
    policy_name = exception.policy.class.to_s.underscore
    flash[:error] = t "#{policy_name}.#{exception.query}", scope: "pundit", default: :default
    redirect_to(request.referred || root_path)
  end
end

Pundit.policy(user, post)
Pundit.policy(user, post)
Pundit.policy_scope!(user, Post)
Pundit.policy_scope(user, Post)

def pundit_user
  User.find_by_other_means
end

auhotize(post)
authorize([:admin, post])
authorize([:foo, :bar, post])
policy_scope(Post)
policy_scope([:admin, Post])
policy_scope([:foo, :bar, Post])

class AdminController < ApplicationController
  def policy_scope(scope)
    super([:admin, scope])
  end
  def authorize(record, query = nil)
    super([:admin, record], query)
  end
end
class Admin::PostController < AdminController
  def index
    policy_scope(Post)
  end
  def show
    post = Post.find(params[:id])
    authorize(post)
  end
end

class UserContext
  attr_reader :user, :ip
  def initialize(user, ip)
    @user = user
    @ip = ip
  end
end
class ApplicationController
  include Pundit
  def pundit_user
    UserContext.new(current_user, request.ip)
  end
end

# app/policies/post_policy.rb
class PostPolicy < ApplicationPolicy
  def permitted_attributes
    if user.admin? || user.owner_of?(post)
      [:title, :body, :tag_list]
    else
      [:tag_list]
    end
  end
end

# app/controllers/posts_controller.rb
class PostsController < ApplicationController
  def update
    @post = Post.find(params[:id])
    if @post.update_attributes(post_params)
      redirect_to @post
    else
      render :edit
    end
  end
  private
  def post_params
    params.require(:post).permit(policy(@post).permitted_attributes)
  end
end

# app/controllers/posts_controller.rb
class PostController < Application
  def update
    @post = Post.find(params[:id])
    if @post.update_attributes(permitted_attributes(@post))
      redirect_to @post
    else
      render :edit
    end
  end
end

# app/policies/post_policy.rb
class PostPolicy < ApplicationPolicy
  def permittted_attributes_for_create
    [:title, :body]
  end
  def permitted_attributes_for_edit
    [:body]
  end
end

def pundit_params_for(record)
  params.require(PolicyFinder.new(record).parma_key)
end

def pundit_params_for(record)
  params.fetch(PolicyFinder.new(record).param_key, {})
end
def pundit_params_for(_record)
  params.fetch(:data, {}).fetch(:attributes, {})
end

require "pundit/rspec"
describe PostPolicy do
  it "denies access if post is published" do
    expect(subject).not_to permit(User.ne(), Post.new(published: true))
  end
  it "grants access if post is published and user is an admin" do
    expect(subject).to permit(User.new(admin: true), Post.new(published: true))
  end
  it "grants access if post is unpublished" do
    expect(subject).to permit(User.new(admin: false), Post.new(published: false))
  end
end

```

```html
<% if policy(@post).update? %>
  <%= link_to "Edit post", edit_post_path(@post) %>
<% end %>

<% if policy(:dashboard).show? %>
  <%= link_to 'Dashboard', dashboard_path %>
<% end %>

<% policy_scope(@user.posts).each do |post| %>
  <p><%= link_to post.title, post_path(post) %></p>
<% end %>

```

```yml
en:
  pundit:
    default: 'You cannot perform this action.'
    post_policy:
      update?: 'You cannot edit this post!'
      create?: 'You cannot create posts!'
```




