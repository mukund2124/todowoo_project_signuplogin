from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth import login, logout, authenticate
from .models import Todo
from .forms import TodoForm
from django.utils import timezone
from django.contrib.auth.decorators import login_required

def home(request):
    return render(request, 'todo/home.html')

def loginuser(request):
    if request.method == 'GET':
        return render(request, 'todo/login.html', {'forms':AuthenticationForm()})
    else:
        user=authenticate(request, username=request.POST['username'], password=request.POST['password'])
        if user is None:
            return render(request, 'todo/login.html', {'forms':AuthenticationForm(), 'error':'----Either username or password is incorrect----'})
        else:
            login(request, user)
            return redirect('currentalogin')

def signupuser(request):
    if request.method == 'GET':
        return render(request, 'todo/signupuser.html', {'forms':UserCreationForm()})
    else:
        # create a new user
        if request.POST['password1'] == request.POST['password2']:
            try:
                user = User.objects.create_user(request.POST['username'], password=request.POST['password1'])
                user.save()
                login(request, user)
                return redirect('currentalogin')

            except IntegrityError:
                return render(request, 'todo/signupuser.html', {'forms': UserCreationForm(),
                                                                'error': '----username already taken. Kindly choose another----'})
        else:
            # tell the user that the password1 does not matches the password2[confirm password]
            return render(request, 'todo/signupuser.html',
                          {'forms': UserCreationForm(), 'error': '----passwords does not match----'})


def currentalogin(request):
    todos = Todo.objects.filter(user=request.user, datecompleted__isnull = True)
    return render(request, 'todo/currentalogin.html', {'todos':todos})

@login_required
def logoutuser(request):
    if request.method == 'POST':
        logout(request)
        return redirect('home')

@login_required
def createtodo(request):
    if request.method == 'GET':
        return render(request, 'todo/createtodo.html', {'forms':TodoForm()})
    else:
        try:
            form = TodoForm(request.POST)
            newtodo = form.save(commit=False)
            newtodo.user = request.user
            newtodo.save()
        except ValueError:
            return render(request, 'todo/createtodo.html', {'forms': TodoForm(), 'error':'too big To-do'} )
        return redirect('currentalogin')

@login_required
def viewstodo(request, todo_pk):
    todo = get_object_or_404(Todo, pk = todo_pk, user=request.user)
    if request.method == 'GET':
        form = TodoForm(instance=todo)
        return render(request, 'todo/viewstodo.html', {'todo': todo, 'form': form})
    else:
        try:
            form = TodoForm(request.POST, instance=todo)
            form.save()
            return redirect('currentalogin')
        except ValueError:
            return render(request, 'todo/viewstodo.html', {'todo': todo, 'form': form, 'error':'invalid info'})

@login_required
def completetodo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk, user=request.user)
    if request.method == 'POST':
        todo.datecompleted = timezone.now()
        todo.save()
        return redirect('currentalogin')

@login_required
def deletetodo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk, user=request.user)
    if request.method == 'POST':
        todo.delete()
        return redirect('currentalogin')

@login_required
def completedtodo(request):
    todos = Todo.objects.filter(user=request.user, datecompleted__isnull=False).order_by('-datecompleted')
    return render(request, 'todo/completedtodo.html', {'todos': todos})