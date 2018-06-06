pipeline {
  agent {
    docker {
      image 'artempikulin/cmake-ubuntu'
    }
    
  }
  stages {
    stage('Build') {
      steps {
        sh '''git submodule update --init --recursive
rm -rf build
mkdir build
cd build
cmake ..
cmake --build . --target marketmaker-testnet'''
      }
    }
  }
}