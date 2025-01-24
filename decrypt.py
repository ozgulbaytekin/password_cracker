import itertools
import string
import multiprocessing
import json
import asyncio
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from encrypt import *  
from tqdm import tqdm  # progress bar için
import time

app = Flask(__name__)
socketio = SocketIO(app)

# Multiprocessing kullanarak paralel şekilde şifre kırma denemelerinin yapıldığı fonksiyon
def attempt_crack(pipe, characters, length, start_index, end_index, hash_to_crack, flag):
    try:
        if start_index >= end_index:
            print(f"[DEBUG] Invalid range: start_index={start_index}, end_index={end_index}")
            pipe.send(None)
            return

        # Processlerin ilerlemesini gösterebilmek için terminalde gösterilecek olan progress bar
        process_progress_bar = tqdm(total=end_index - start_index, desc=f"Process {start_index}-{end_index}", ncols=100, unit="password")
        
        # Olası şifre kombinasyonlarının üretildiği kısım
        for idx, candidate in enumerate(itertools.islice(itertools.product(characters, repeat=length), start_index, end_index)):
            if flag.value == 1:
                pipe.send(None)
                return

            password = ''.join(candidate)
            process_progress_bar.update(1)  # Progress bar'ı güncelliyoruz

            # Ürettiğimiz şifre ile denenen kombinasyonun uyuşup uyuşmadığını kontrol ediyoruz
            if check_password(password):  # encrypt.py dosyasındaki check_password fonksiyonu
                pipe.send(password)  # Bulunan şifre main process'e gönderiliyor
                flag.value = 1
                process_progress_bar.close()  # Şifre bulunduktan sonra progress bar durduruluyor
                return

        pipe.send(None)  # Şifre bulunamadıysa none dönüyor
        process_progress_bar.close()  # Progress bar kapatılıyor
    except Exception as e:
        pipe.send(f"Error: {str(e)}")
        print(f"[DEBUG] Error in process: {str(e)}")

# Şifre kırma denemelerinin birden fazla processe dağıtıldığı asenkron fonksiyon
async def distribute_tasks(hash_to_crack, socket):
    characters = string.ascii_lowercase + " "  # Karakter setinin belirtildiği kısım, harfler ve sayılardan oluşuyor
    length = 6  # Kırılacak şifrenin basamak sayısı
    total_combinations = len(characters) ** length  #  Karakterlerin toplam kombinasyonları
    num_processes = multiprocessing.cpu_count()  # Toplam process sayısı, sistemdeki CPU sayısına göre belirleniyor
    chunk_size = total_combinations // num_processes  # Dağıtılacak her parçanın büyüklüğü, her process'in ne kadar kombinasyon deneyeceği

    processes = []
    pipes = []
    flag = multiprocessing.Value('i', 0)  # Processler için ortak flag, şifre bulunma durumunu kontrol ediyor

    # Process'lerin oluşturduğu ve task'ların dağıtıldığı döngü
    for i in range(num_processes):
        start_index = i * chunk_size
        end_index = start_index + chunk_size if i < num_processes - 1 else total_combinations #son process'te tüm kombinasyon saysını end_index olarak belirtiyoruz
        parent_conn, child_conn = multiprocessing.Pipe()
        #parent_conn main process'i, child_con sub process'i belirtiyor
        process = multiprocessing.Process(
            target=attempt_crack, #subprocess attemp_crack fonksiyonunu çağırıyor
            args=(child_conn, characters, length, start_index, end_index, hash_to_crack, flag)
        )
        processes.append(process)
        pipes.append(parent_conn)
        process.start()

    # Tüm process'lerin bitmesini bekliyoruz
    for process in processes:
        process.join()

    # Process'lerin sonuçları kontrol ediliyor
    for pipe in pipes:
        result = pipe.recv()
        if result:
            return result  # Bulunan şifre geri dönüyor
    return None  # Şifre bulunamadıysa none dönüyor


#Şifre kırma işleminin başlatıldığı ana fonksiyon, exception handling burada yapılıyor
async def main(socket):
    try:
        # get_password fonksiyonu çağırılarak şifre üretme fonksiyonu tetikleniyor ve üretilen şifre json dosyasına kaydediliyor
        get_password()  
        # Üretilen hash'li şifre dosyadan okunuyor
        with open("password.json", "r") as f:
            stored_password_hash = json.load(f).get("password")

        return await distribute_tasks(stored_password_hash, socket)  # Task'lar dağıtılıyor
    except Exception as e:
        print(f"[DEBUG] Error in main: {str(e)}")
        return None  # Hata durumunda none dönüyor

# Anasayfanın yüklediği kısım
@app.route('/')
def index():
    return render_template('index.html')


#Şifre kırmanın başlatıldığı ve sonucun döndürüldüğü fonksiyon
@app.route('/crack_password', methods=["GET"])
def crack_password():
    try:
        start_time = time.time()  # Başlangıç zamanı
        result = asyncio.run(main(socketio))  # Asenkron olarak şifre kırmanın başlatıldığı kısım
        end_time = time.time()  # Bitiş zamanı

        # Saniye cinsinden programın çalışma süresini hesaplıyoruz
        time_taken = f"{end_time - start_time:.3f} seconds"

        # Kırılan şifreyi ve geçen zamanı yazdırıyoruz
        if result:
            socketio.emit('password_cracked', {'password': result, 'time': time_taken})
            return jsonify({"status": "Password cracked!", "password": result, "time": time_taken})
        else:
            return jsonify({"status": "Failed to crack the password", "password": None, "time": time_taken})
    except Exception as e:
        return jsonify({"status": f"Error: {str(e)}", "password": None, "time": "N/A"})




if __name__ == "__main__":
    socketio.run(app, debug=True, port=5014)  
