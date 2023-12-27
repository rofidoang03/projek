import instaloader
import sys

def download_posts(username):
    loader = instaloader.Instaloader()

    try:
        profile = instaloader.Profile.from_username(loader.context, username)
        for post in profile.get_posts():
            loader.download_post(post, target=profile.username)
        print("Download complete")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python download_instagram.py <username_target>")
    else:
        target_username = sys.argv[1]
        download_posts(target_username)
        
