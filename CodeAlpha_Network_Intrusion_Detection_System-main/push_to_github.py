#!/usr/bin/env python3
import os
import sys
from git import Repo
from git.exc import InvalidGitRepositoryError, GitCommandError

# Configuration
REPO_PATH = "c:/Users/RONALDO/Desktop/CodeAlpha_Network_Intrusion_Detection_System-main"
GITHUB_URL = "https://github.com/priyanshuronaldo07/CodeAlpha_CyberSecurity.git"
BRANCH_NAME = "main"

def setup_git_repo():
    """Initialize git repository and configure it"""
    try:
        # Try to open existing repo
        repo = Repo(REPO_PATH)
        print(f"✓ Found existing git repository at {REPO_PATH}")
    except InvalidGitRepositoryError:
        # Initialize new repo
        print(f"Initializing new git repository at {REPO_PATH}...")
        repo = Repo.init(REPO_PATH)
        print("✓ Git repository initialized")
    
    return repo

def add_remote(repo):
    """Add GitHub remote if it doesn't exist"""
    try:
        origin = repo.remote('origin')
        print(f"✓ Remote 'origin' already configured: {origin.url}")
    except ValueError:
        print(f"Adding remote 'origin': {GITHUB_URL}")
        repo.create_remote('origin', GITHUB_URL)
        print("✓ Remote 'origin' added")

def push_code(repo):
    """Add files, commit, and push to GitHub"""
    try:
        # Add all files
        print("\nAdding files...")
        repo.git.add(A=True)
        print("✓ Files added to staging area")
        
        # Check if there are changes to commit
        if repo.index.diff("HEAD"):
            print("\nCommitting changes...")
            repo.index.commit("Add Network Intrusion Detection System code")
            print("✓ Changes committed")
        else:
            print("ℹ No changes to commit")
        
        # Push to GitHub
        print(f"\nPushing to {GITHUB_URL}...")
        origin = repo.remote('origin')
        origin.push(BRANCH_NAME)
        print(f"✓ Successfully pushed to {BRANCH_NAME} branch")
        
    except GitCommandError as e:
        print(f"✗ Git error: {e}")
        print("\nMake sure you have:")
        print("1. GitHub account configured with SSH or HTTPS credentials")
        print("2. Write access to the repository")
        print("3. Internet connection")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)

def main():
    """Main function"""
    print("="*60)
    print("GitHub Repository Push Tool")
    print("="*60)
    print(f"Repository Path: {REPO_PATH}")
    print(f"GitHub URL: {GITHUB_URL}")
    print(f"Branch: {BRANCH_NAME}")
    print("="*60)
    
    try:
        repo = setup_git_repo()
        add_remote(repo)
        push_code(repo)
        
        print("\n" + "="*60)
        print("✓ Successfully pushed code to GitHub!")
        print("="*60)
        
    except Exception as e:
        print(f"\n✗ Failed to push to GitHub: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
