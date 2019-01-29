
package main

import "os"
import "fmt"
import "log"
import "net/http"
import "time"
import "reflect"
import "flag"
import "errors"
import "strings"
import "io/ioutil"
import "crypto/x509"
import "encoding/pem"
import "crypto/x509/pkix"

func getCACert(file string) (caCert *x509.Certificate, contents []byte, err error) {
  caContents, err := ioutil.ReadFile(file)
  if err != nil {
    return
  }

  caPEMBlock, _ := pem.Decode(caContents)
  if caPEMBlock == nil {
    return nil, caContents, errors.New("Failed to decode CA contents as PEM")
  }
  if caPEMBlock.Type != "CERTIFICATE" {
    return nil, caContents, errors.New(fmt.Sprint("CA file", file, "did not contain a CA certificate"))
  }

  result, err := x509.ParseCertificate(caPEMBlock.Bytes)
  return result, caContents, err
}

func caNeedsUpdate(file string) bool {
  crl_file := strings.TrimSuffix(file, ".0") + ".r0"
  if _, err := os.Stat(file); err != nil {
    return true
  }
  crl_stat, err := os.Stat(crl_file)
  if err != nil {
    return true
  }
  force_update := 6 * time.Hour
  if time.Since(crl_stat.ModTime()) > force_update {
    return true
  }

  contents, err := ioutil.ReadFile(crl_file)
  if err != nil {
    return true
  }
  crl, err := x509.ParseCRL(contents)
  if err != nil {
    return true
  }
  if time.Now().Add(force_update).After(crl.TBSCertList.NextUpdate) {
    return true
  }
  return false
}

func getCrlUrls(file string) (crls []string, err error) {

  ca, _, err := getCACert(file)
  if err != nil {
    return
  }

  return ca.CRLDistributionPoints, nil;
}

type TrustRootResult struct {
  ca *x509.Certificate
  filename string
  contents []byte
  err error
}


// TODO(bbockelm): Skip trust roots that don't need any updates.
func getTrustRoots(cadir string, outputdir string, timeout <-chan time.Time) (result chan TrustRootResult) {

  result = make(chan TrustRootResult)

  // Note: on face, it looks like a crazy over-optimization to parallelize parsing
  // of the CA directory.  However, this is done for the case where the CAs might be on a
  // remote filesystem (such as CVMFS) and have to be brought in from the server.
  helpers := 4

  filenames := make(chan string)
  resultChannels := make([]reflect.SelectCase, helpers+1, helpers+1)
  resultChannels[0] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(timeout)}
  for i := 0; i < helpers; i+= 1 {
    resultChan := make(chan TrustRootResult)
    resultChannels[i+1] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(resultChan)}
    go func() {
      for file := range filenames {
        if !caNeedsUpdate(outputdir + "/" + file) {
          continue
        }
        ca, contents, err := getCACert(cadir + "/" + file)
        resultChan <- TrustRootResult{ca, file, contents, err}
      }
      close(resultChan)
    }()
  }
  //log.Println("Created directory parse helpers")

  go func() {
    files, err := ioutil.ReadDir(cadir)
    if err != nil {
      log.Fatal(err)
    }
    for _, file := range files {
      if strings.HasSuffix(file.Name(), ".0") {
        //log.Println("Sending CA", file.Name())
        filenames <- file.Name()
      }
    }
    close(filenames)
  }()

  go func() {
    remaining := helpers
    for remaining > 1 {
      chosen, value, ok := reflect.Select(resultChannels)
      if chosen == 0 {
        log.Fatal("Timeout when parsing the CA directory")
      }
      if !ok {
        resultChannels[chosen].Chan = reflect.ValueOf(nil)
        remaining -= 1
        continue
      }
      result <- value.Interface().(TrustRootResult)
      //log.Println("Sending upstream result")
    }
    close(result)
  }()

  return result
}

type FetchCRLResult struct {
  crl *pkix.CertificateList
  url string
  contents []byte
  err error
}

func fetchCRL(crl_url string, results chan FetchCRLResult) {
  log.Println("Updating CRL from", crl_url)
  result := FetchCRLResult{url: crl_url}
  resp, err := http.Get(crl_url)
  if err != nil {
    result.err = err
    results <- result
    return
  }

  defer resp.Body.Close()
  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    result.err = err
    results <- result
    return
  }
  log.Println("Got result from", crl_url)

  crl, err := x509.ParseCRL(body)
  if err == nil {
    result.contents = body
  }
  result.crl = crl
  result.err = err
  results <- result
}

func atomicWrite(dirname string, prefix string, data []byte) (err error) {
  if file, err := ioutil.TempFile(dirname, prefix + ".tmp"); err == nil {
    if _, err := file.Write(data); err == nil {
      file.Chmod(0644)
      if err := os.Rename(file.Name(), dirname + "/" + prefix); err != nil {
        os.Remove(file.Name())
      }
    } else {
      os.Remove(file.Name())
    }
  }
  return
}

func verifyAndUpdate(crl FetchCRLResult, outputdir string, cas []*x509.Certificate, trust_roots []TrustRootResult, update_results chan error) {

  verify_signer := false
  for _, ca := range cas {
    if err := ca.CheckCRLSignature(crl.crl); err == nil {
      verify_signer = true
      break
    }
  }
  if !verify_signer {
    for idx := 0; idx < len(trust_roots); idx += 1 {
      update_results <- errors.New("CRL has no valid signers")
    }
    log.Println("CRL", crl.url, "verification failed")
    return
  }

  for _, root := range trust_roots {
    // Write trust root if it's not present
    if _, err := os.Stat(outputdir + "/" + root.filename); os.IsNotExist(err) {
      if err := atomicWrite(outputdir, root.filename, root.contents); err != nil {
        log.Println("Failed to write CA file:", outputdir + "/" + root.filename, ";", err)
        update_results <- err
        continue
      }
    }

    // Write CRL
    crl_filename := strings.TrimSuffix(root.filename, ".0") + ".r0"
    if err := atomicWrite(outputdir, crl_filename, crl.contents); err != nil {
      log.Println("Failed to write CRL file:", outputdir + "/" + crl_filename, ";", err)
      update_results <- err
    } else {
      log.Println("Wrote CRL", crl_filename)
      update_results <- nil
   }
  }
}


func main() {

  certdir_flag := flag.String("cadir", "", "Non-standard location of trusted cert dir")
  outputdir := flag.String("output", "", "Location of the output CRLs (defaults to cadir)")

  flag.Parse();

  certdir := "/etc/grid-security/certificates"
  if len(*certdir_flag) == 0 {
    if certdir_tmp := os.Getenv("X509_CERT_DIR"); len(certdir_tmp) > 0 {
      certdir = certdir_tmp
    }
  } else {
    certdir = *certdir_flag
  }

  if len(*outputdir) == 0 {
    *outputdir = certdir;
  }

  crl_to_cas := make(map[string][]TrustRootResult)
  fetchCRLResults := make(chan FetchCRLResult)

  timeout := time.After(1 * time.Minute)

  expected_results := 0
  expected_updates := 0
  problem_parsing_cas := 0
  cas := make([]*x509.Certificate, 0, 250)
  trustRootsChan := getTrustRoots(certdir, *outputdir, timeout)
  for result := range trustRootsChan {
    if result.err != nil {
        log.Println("Problem parsing CA", result.filename, ":", result.err)
        problem_parsing_cas += 1
        continue
    } else {
      //log.Println("Successfully parsed CA", result.filename)
    }
    cas = append(cas, result.ca)
    for _, crl_url := range result.ca.CRLDistributionPoints {
      ca_list, ok := crl_to_cas[crl_url]
      expected_updates += 1
      if ok {
        crl_to_cas[crl_url] = append(ca_list, result)
      } else {
        tmp_cas := make([]TrustRootResult, 1, 2)
        tmp_cas[0] = result
        crl_to_cas[crl_url] = tmp_cas
        go fetchCRL(crl_url, fetchCRLResults)
        expected_results += 1
      }
    }
  }

  if problem_parsing_cas > 0 {
    log.Println("CA parsing problems", problem_parsing_cas)
  }

  update_results := make(chan error)
  go func() {
    problem_fetching_crls := 0
    for expected_results > 0 {
      result := <- fetchCRLResults
      expected_results -= 1
      if result.err != nil {
        log.Println("Error when fetching CRL:", result.err)
        problem_fetching_crls += 1
        for idx := 0; idx < len(crl_to_cas[result.url]); idx++ {
          update_results <- result.err
        }
      } else {
        // CRL has been fetched; now verify.
        go verifyAndUpdate(result, *outputdir, cas, crl_to_cas[result.url], update_results)
      }
    }
    if problem_fetching_crls > 0 {
      log.Println("Failed to fetch")
    }
  }()

  problem_updating_crls := 0
  for expected_updates > 0 {
    select {
      case result := <- update_results:
        expected_updates -= 1
        if result != nil {
          log.Println("Error when updating CRL:", result)
          problem_updating_crls += 1
        }
        //log.Println("There are ", expected_updates, " remaining")
      case <-timeout:
        log.Fatal("Timeout when waiting for ", expected_updates, " CRLs to download")
    }
  }
  if problem_updating_crls > 0 {
    log.Fatal("Errors updating ", problem_updating_crls, " CRLs")
  } else {
    log.Println("All CRLs updated successfully.")
  }
}

