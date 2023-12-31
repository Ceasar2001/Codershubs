from unicodedata import category
from django import forms
from django.contrib.auth.forms import UserCreationForm

from django.contrib.auth.models import User
from coderapp.models import UserProfile, Category, Post


class UserRegistration(UserCreationForm):
    email = forms.EmailField(
        max_length=250, help_text="The email field is required.")
    first_name = forms.CharField(
        max_length=250, help_text="The First Name field is required.")
    middle_name = forms.CharField(
        max_length=250, help_text="The Middle Name field is required.")
    last_name = forms.CharField(
        max_length=250, help_text="The Last Name field is required.")

    class Meta:
        model = User
        fields = ('email', 'username', 'password1', 'password2', 'first_name', 'middle_name', 'last_name')
        

    def clean_email(self):
        email = self.cleaned_data['email']
        try:
            user = User.objects.get(email=email)
        except Exception as e:
            return email
        raise forms.ValidationError(
            f"The {user.email} mail is already exists/taken")

    def clean_username(self):
        username = self.cleaned_data['username']
        try:
            user = User.objects.get(username=username)
        except Exception as e:
            return username
        raise forms.ValidationError(
            f"The {user.username} mail is already exists/taken")


class UpdateProfile(forms.ModelForm):
    username = forms.CharField(
        max_length=250, help_text="The Username field is required.")
    email = forms.EmailField(
        max_length=250, help_text="The Email field is required.")
    first_name = forms.CharField(
        max_length=250, help_text="The First Name field is required.")
    middle_name = forms.CharField(
        max_length=250, help_text="The Middle Name field is required.")
    last_name = forms.CharField(
        max_length=250, help_text="The Last Name field is required.")
    current_password = forms.CharField(max_length=250)
    
    class Meta:
        model = User
        fields = ('email', 'username', 'first_name',
                  'middle_name', 'last_name')

    def clean_current_password(self):
        if not self.instance.check_password(self.cleaned_data['current_password']):
            raise forms.ValidationError(f"Password is Incorrect")

    def clean_email(self):
        email = self.cleaned_data['email']
        try:
            user = User.objects.exclude(
                id=self.cleaned_data['id']).get(email=email)
        except Exception as e:
            return email
        raise forms.ValidationError(
            f"The {user.email} mail is already exists/taken")

    def clean_username(self):
        username = self.cleaned_data['username']
        try:
            user = User.objects.exclude(
                id=self.cleaned_data['id']).get(username=username)
        except Exception as e:
            return username
        raise forms.ValidationError(
            f"The {user.username} mail is already exists/taken")

class ProfileUpdateForm(forms.Form):
    new_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control rounded-0'}))

class UpdateProfileMeta(forms.ModelForm):
    middle_name = forms.CharField(
        max_length=250, help_text="The Middle Name field is required.")
    class Meta:
        model = UserProfile
        fields = ('middle_name',)


class UpdateProfileAvatar(forms.ModelForm):
    avatar = forms.ImageField(help_text="The Avatar field is required.")
    current_password = forms.CharField(max_length=250)

    class Meta:
        model = UserProfile
        fields = ('avatar',)

    def __init__(self, *args, **kwargs):
        self.user = kwargs['instance']
        kwargs['instance'] = self.user.profile
        super(UpdateProfileAvatar, self).__init__(*args, **kwargs)

    def clean_current_password(self):
        if not self.user.check_password(self.cleaned_data['current_password']):
            raise forms.ValidationError("Password is Incorrect")


class AddAvatar(forms.ModelForm):
    avatar = forms.ImageField(help_text="The Avatar field is required.")

    class Meta:
        model = UserProfile
        fields = ('avatar',)

class SaveCategory(forms.ModelForm):
    name = forms.CharField(
        max_length=250, help_text="Category Name Field is required.")
    description = forms.Textarea()
    status = forms.ChoiceField(help_text="Category Name Field is required.", choices=(
        ('1', 'Active'), ('2', 'Inctive')))

    class Meta:
        model = Category
        fields = ('name', 'description', 'status',)

    def clean_name(self):
        name = self.cleaned_data['name']
        id = self.instance.id if not self.instance == None else ''
        try:
            if id.isnumeric() and id != '':
                Category = Category.objects.exclude(id=id).get(name=name)
            else:
                Category = Category.objects.get(name=name)
        except Exception as e:
            if name == '':
                raise forms.ValidationError(f"Category field is required.")
            else:
                return name
        raise forms.ValidationError(f"{name} Category already exists.")


class SavePost(forms.ModelForm):
    category = forms.IntegerField()
    author = forms.IntegerField()
    title = forms.Textarea()
    code_post = forms.Textarea()
    status = forms.ChoiceField(help_text="Status Field is required.", choices=(
        ('1', 'Published'), ('2', 'Unpublished')))

    def __init__(self, *args, **kwargs):
        super(SavePost, self).__init__(*args, **kwargs)

    class Meta:
        model = Post
        fields = ('category', 'author', 'title',
                  'code_post', 'status', 'banner')

    def clean_category(self):
        catId = self.cleaned_data['category']
        try:
            category = Category.objects.get(id=catId)
            return category
        except:
            raise forms.ValidationError(f"Invalid Category Value.")

    def clean_author(self):
        userId = self.cleaned_data['author']
        try:
            author = User.objects.get(id=userId)
            return author
        except:
            raise forms.ValidationError(f"Invalid User Value.")
        
##
class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ['name', 'description', 'status']