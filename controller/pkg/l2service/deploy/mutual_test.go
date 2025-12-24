package deploy

import (
	"fmt"
	"os/user"
	"testing"
	"time"
)

var (
	currentUser, _ = user.Current()
)

func TestEmptyPublicKey(t *testing.T) {
	targetAuth := &TargetWithAuth{
		Auth: Auth{
			Username: "swk",
			Password: "BrY3j&hHrh1",
		},
		Host:      "10.45.7.147",
		LoginType: LOGIN_PASSWORD,
	}
	if targetAuth.checkKeyFile() == true {
		t.Error("checkFileFile is not working prefect")
	}
}

var validPublicKeyTest = []TargetWithAuth{
	TargetWithAuth{
		Auth: Auth{
			Username:  "swk",
			Password:  "BrY3j&hHrh1",
			PublicKey: currentUser.HomeDir + "/.ssh/id_rsa.pub",
		},
		Host:      "10.45.7.147",
		LoginType: LOGIN_MUTUAL,
	},
}

func TestPublicKey(t *testing.T) {
	for _, targetAuth := range validPublicKeyTest {
		if targetAuth.checkKeyFile() == false {
			t.Error(targetAuth.Error())
		}
	}
}

func TestForceMutual(t *testing.T) {
	for _, targetAuth := range validPublicKeyTest {
		targetAuth.WithForceMutual()
		if targetAuth.Mutualed != true {
			t.Error(targetAuth.Error())
		}
	}
}

var validMutualTest = []TargetWithAuth{
	TargetWithAuth{
		Auth: Auth{
			Username:  "swk",
			Password:  "BrY3j&hHrh1",
			PublicKey: currentUser.HomeDir + "/.ssh/id_rsa.pub",
		},
		Host:      "10.45.7.147",
		LoginType: LOGIN_MUTUAL,
	},
}

func TestMutual(t *testing.T) {
	for _, targetAuth := range validMutualTest {
		got := targetAuth.mutual()
		if got == false {
			t.Error(targetAuth.Error())
		}
		if targetAuth.Mutualed != true {
			t.Error(targetAuth.Error())
		}

		time.Sleep(1 * time.Second)

		// targetAuth.ClearAuthorizedOnRemote()
	}

}

func TestSshLoginWithPassword(t *testing.T) {
	targetAuth := &TargetWithAuth{
		Auth: Auth{
			Username: "swk",
			Password: "BrY3j&hHrh1",
		},
		Host:      "10.45.7.147",
		LoginType: LOGIN_PASSWORD,
	}

	_, err := targetAuth.CheckSshLogin()
	if err != nil {
		t.Error(err)
	}
}

func TestSshExecuteCmd(t *testing.T) {
	targetAuth := NewTargetWithAuth("swk", "BrY3j&hHrh1", "10.45.7.147")
	targetAuth.WithPublicKey(currentUser.HomeDir + "/.ssh/id_rsa.pub").WithLoginType(LOGIN_MUTUAL)
	// targetAuth := &TargetWithAuth{
	// 	Auth: Auth{
	// 		Username:  "swk",
	// 		Password:  "BrY3j&hHrh1",
	// 		PublicKey: currentUser.HomeDir + "/.ssh/id_rsa.pub",
	// 	},
	// 	Host:      "10.45.7.147",
	// 	LoginType: LOGIN_MUTUAL,
	// }

	// ok := targetAuth.mutual()
	// if !ok {
	// 	t.Error(targetAuth.Error())
	// }

	output, err := targetAuth.ExecuteCmd([]string{"ls", "cd /media", "ls"}, 2)
	if err != nil {
		t.Error(fmt.Sprintf("output: %s, err: %s", output, err))
	}
}

func TestSshExecuteCmdWithPassword(t *testing.T) {
	targetAuth := &TargetWithAuth{
		Auth: Auth{
			Username: "swk",
			Password: "BrY3j&hHrh1",
		},
		Host:      "10.45.7.147",
		LoginType: LOGIN_PASSWORD,
	}
	//
	// ok := targetAuth.mutual()
	// if !ok {
	// t.Error(targetAuth.Error())
	// }

	output, err := targetAuth.ExecuteCmd([]string{"ls", "cd /media", "ls"}, 2)
	// fmt.Println(output)
	if err != nil {
		t.Error(fmt.Sprintf("output: %s, err: %s", output, err))
	}
}

func TestSshKillProcess(t *testing.T) {

	targetAuth := &TargetWithAuth{
		Auth: Auth{
			Username:  "swk",
			Password:  "BrY3j&hHrh1",
			PublicKey: currentUser.HomeDir + "/.ssh/id_rsa.pub",
		},
		Host:      "10.45.7.147",
		LoginType: LOGIN_MUTUAL,
	}

	go targetAuth.ExecuteCmd([]string{"ping 202.96.209.5"}, 10)
	time.Sleep(5 * time.Second)

	// output, err := targetAuth.ExecuteCmd([]string{"ls", "cd /media", "ls"}, 2)
	// fmt.Println(output)
	output, err := targetAuth.KillProcess("ping")
	if err != nil {
		t.Error(fmt.Sprintf("output: %s, err: %s", output, err))
	}

	fmt.Println(output)
}
